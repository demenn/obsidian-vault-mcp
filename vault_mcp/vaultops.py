"""Vault file operations for the Obsidian vault MCP server.

Everything that touches the vault lives here, deliberately free of any fastmcp
import: ``server.py`` builds a ``FastMCP`` instance at import time, which makes
it impossible to exercise in an offline test — and this package had no tests at
all. ``server.py`` keeps auth, the YouTube tool and thin ``@mcp.tool`` wrappers;
the tool docstrings stay there because they are the contract the model reads.

The write contract (atomic writes, "no change → no write", ``expected_hash``,
``dry_run``, the audit journal, deletion into ``.trash/``) is specified in
``docs/write-contract.md``. Read that before changing behaviour here — the
reasoning for every choice lives in it, not in these comments.
"""
from __future__ import annotations

import contextvars
import difflib
import functools
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

# Shared naming rules, vendored in this package as ``naming.py`` so the server
# is self-contained; nothing here may grow dependencies beyond the stdlib + yaml.
from .naming import note_id, safe_stem

# Identity of the caller for the current request, filled by the server's
# AllowListMiddleware (which already extracts the claim from the access token).
# Without it the journal cannot answer "who deleted this".
CURRENT_USER: contextvars.ContextVar[str] = contextvars.ContextVar(
    "mcp_current_user", default=""
)
# How the caller authenticated: "" for OAuth (the journal format for humans
# stays byte-identical), "static" for a pre-issued machine-account token.
CURRENT_AUTH: contextvars.ContextVar[str] = contextvars.ContextVar(
    "mcp_current_auth", default=""
)
# Per-account tool policy from the static token file: names of mutating tools
# this caller may not use, or {READONLY_ALL} for "none of them". Empty for
# humans. Checked in `_journaled` — the one place that knows the tool name.
READONLY_ALL = "*"
CURRENT_DENIED_TOOLS: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "mcp_current_denied_tools", default=frozenset()
)
# Every tool name registered through `_journaled`, filled at import time. This
# is what a `deny=` policy may name, and what the offline test compares the
# server's `@mcp.tool` list against — a writing tool added outside `Vault`
# would bypass the policy silently, so it must fail that test instead.
MUTATING_TOOLS: set[str] = set()

# Folders that are noise for an LLM browsing the vault: machine dirs plus
# whatever the operator declares. Override with VAULT_EXCLUDE_DIRS (comma-
# separated folder names, matched anywhere in the path, e.g.
# "90_Archive,20_Attachments").
EXCLUDE_PARTS = tuple(
    f"/{d.strip()}/"
    for d in os.environ.get(
        "VAULT_EXCLUDE_DIRS", ".obsidian,.git,.trash"
    ).split(",")
    if d.strip()
)

# Link rewriting walks WIDER than browsing: a link to a renamed note also lives
# on a kanban board under _boards/ and in entity stubs, and not rewriting those
# breaks the card. Only machine dirs and the trash are off limits here.
LINK_SKIP_PARTS = ("/.obsidian/", "/.git/", "/.trash/")

TRASH_REL = ".trash"

_FM_RE = re.compile(r"^---\n(.*?)\n---\n?(.*)$", re.DOTALL)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
# Inline #tag (supports nested a/b); preceded by start-of-line or whitespace.
_INLINE_TAG_RE = re.compile(r"(?:^|\s)#([A-Za-zЀ-ӿ][\w/\-]*)", re.UNICODE)
# Wikilink target (the bit before any #heading or |alias).
_WIKILINK_RE = re.compile(r"\[\[([^\]|#]+)(?:[#|][^\]]*)?\]\]")


def fence_flags(lines: list[str]) -> list[bool]:
    """Per line: True when the line sits inside a fenced code block.

    Notes carry code blocks whose lines may start with '#' or contain '#tag';
    treating those as headings or tags corrupts structural edits (a
    delete_section by such a "heading" cuts the block open, a rename rewrites
    text inside it). The fence lines themselves are flagged too.
    """
    flags: list[bool] = []
    in_fence = False
    for ln in lines:
        is_fence = ln.lstrip().startswith("```")
        flags.append(in_fence or is_fence)
        if is_fence:
            in_fence = not in_fence
    return flags


# Chars a filename must not carry: forbidden by a filesystem, or impossible to
# write inside `[[…]]` (`#` there means "heading in that note", not the name).


class VaultError(Exception):
    """Anything the caller did wrong; the server renders it as ``ERROR: …``."""


class NotFound(VaultError):
    pass


class Conflict(VaultError):
    pass


class ReadOnly(VaultError):
    pass


class PolicyDenied(VaultError):
    """The caller's account policy forbids this tool (static token `deny=`)."""


def check_policy(tool: str) -> None:
    """Refuse `tool` if the current caller's policy forbids it.

    Runs BEFORE the tool body touches the filesystem, so a denied delete never
    reaches `.trash/` and a denied dry-run never computes a diff. The global
    MCP_READONLY switch is separate (`_require_writable`) and outranks this.
    """
    denied = CURRENT_DENIED_TOOLS.get()
    if not denied:
        return
    user = CURRENT_USER.get() or "?"
    if READONLY_ALL in denied:
        raise ReadOnly(f"server is read-only for user '{user}'")
    if tool in denied:
        raise PolicyDenied(f"tool '{tool}' is denied for user '{user}'")


def split_frontmatter(text: str):
    """Return (frontmatter_dict_or_None, body). dict is None when no frontmatter."""
    m = _FM_RE.match(text)
    if not m:
        return None, text
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        data = None
    if not isinstance(data, dict):
        data = {}
    return data, m.group(2)


def join_frontmatter(data: dict | None, body: str) -> str:
    if not data:
        return body.lstrip("\n")
    fm = yaml.safe_dump(data, allow_unicode=True, sort_keys=False).rstrip("\n")
    return f"---\n{fm}\n---\n\n{body.lstrip(chr(10))}"


def canonical_int(value: str):
    """int(value) when the string is its own canonical decimal form, else None.

    str(int(value)) == value types exactly what int() parses and prints back
    unchanged: "2" -> 2, "-2" -> -2. Everything else stays a string: leading
    zeros ("007"), an explicit plus ("+2"), padding (" 2 "), non-numbers
    ("true"), unicode digits — for those int() either fails or prints a
    different string back (spec 2026-10-05-edit-frontmatter-unquoted).
    """
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value else None


def note_tags(data, body: str) -> set[str]:
    """Collect normalized tags from frontmatter (`tags`) and inline #tags."""
    tags: set[str] = set()
    if isinstance(data, dict):
        ft = data.get("tags")
        if isinstance(ft, str):
            tags.update(re.split(r"[,\s]+", ft))
        elif isinstance(ft, list):
            tags.update(str(x) for x in ft)
    # plain zip: fence_flags matches splitlines length, and strict= needs 3.10
    for ln, fenced in zip(body.splitlines(), fence_flags(body.splitlines())):  # noqa: B905
        if fenced:
            continue
        for m in _INLINE_TAG_RE.finditer(ln):
            tags.add(m.group(1))
    return {t.lstrip("#").strip().lower() for t in tags if t and t.strip()}


def slugify(title: str) -> str:
    s = re.sub(r"\s+", "-", title.strip().lower())
    s = re.sub(r"[^\w\-]", "", s, flags=re.UNICODE)
    return s[:40].strip("-") or "note"


def filename(title: str) -> str:
    """A note filename that keeps the title readable AND linkable — the
    vendored rule (`naming.safe_stem`: illegal and link-hostile characters
    folded, ext4-safe byte budget with a ` (hash)` suffix for the rare
    over-long title), so every note this server creates is named by one
    consistent rule."""
    return safe_stem(title).rstrip(". ") or "note"


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find_section(lines: list[str], heading: str):
    """Locate a section by heading.

    Returns ``(head_index, level, end)`` where the body is ``lines[head_index+1:end]``.
    An empty ``heading`` addresses the PREAMBLE — everything before the first
    heading — and yields ``head_index == -1`` (so the body still starts at 0).
    Returns None when a non-empty heading is not found. Nested anchors use
    "Parent::Child" and only match inside the parent's subtree: a heading of
    the parent's level or higher closes the parent. Lines inside fenced code
    blocks never count as headings.
    """
    fenced = fence_flags(lines)
    if not heading.strip():
        end = len(lines)
        for i, ln in enumerate(lines):
            if not fenced[i] and _HEADING_RE.match(ln):
                end = i
                break
        return -1, 0, end

    wanted = [h.strip() for h in heading.split("::") if h.strip()]
    hi = hlevel = None
    depth = 0
    anchor_level = 0
    for i, ln in enumerate(lines):
        if fenced[i]:
            continue
        m = _HEADING_RE.match(ln)
        if not m:
            continue
        level = len(m.group(1))
        if depth and level <= anchor_level:
            depth = 0  # this heading closed the parent: the chain restarts
        if m.group(2).strip() == wanted[depth]:
            if depth == 0:
                anchor_level = level
            depth += 1
            if depth == len(wanted):
                hi, hlevel = i, level
                break
    if hi is None:
        return None

    end = hi + 1
    while end < len(lines):
        m = None if fenced[end] else _HEADING_RE.match(lines[end])
        if m and len(m.group(1)) <= hlevel:
            break
        end += 1
    return hi, hlevel, end


def rewrite_links(text: str, old_stem: str, new_stem: str) -> str:
    """Repoint every reference to ``old_stem`` at ``new_stem``.

    Knows all three forms a reference can take (wikilink, frontmatter scalar,
    quoted path). The ``\\\\?`` before
    ``[#|]`` matters: inside a markdown table the pipe is escaped, and without
    it exactly the links in tables break.
    """
    alt = re.escape(old_stem)
    text = re.sub(
        rf"\[\[((?:[^\]|#]*/)?)({alt})((?:\\?[#|][^\]]*)?)\]\]",
        lambda m: f"[[{m.group(1)}{new_stem}{m.group(3)}]]",
        text,
    )
    text = re.sub(
        rf'^(\s*(?:-\s*)?[A-Za-z0-9_.-]+:\s*)("?){alt}("?)\s*$',
        lambda m: f"{m.group(1)}{m.group(2)}{new_stem}{m.group(3)}",
        text,
        flags=re.M,
    )
    text = re.sub(
        rf'"([^"]*?/)({alt})\.md"',
        lambda m: f'"{m.group(1)}{new_stem}.md"',
        text,
    )
    return text


def _journaled(tool: str, path_arg: str = "path"):
    """Journal a REFUSAL of a write tool, then re-raise.

    Successes are logged inside ``_commit``; refusals never reach it, and a
    refused delete or a conflict is exactly what somebody auditing the server
    later wants to see. OSError lands here too: a file that vanished between
    the existence check and the read is a refusal like any other, and without
    this branch it would leave a hole in the journal and reach the caller as
    a raw traceback instead of the unified ``ERROR:`` shape. Keeping this as
    a decorator on the public methods means the deep raise sites
    (``check_expected``, ``_existing``, ``_require_writable``) stay ignorant
    of which tool called them.
    """

    MUTATING_TOOLS.add(tool)

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            def refuse(error: str):
                names = fn.__code__.co_varnames[1:fn.__code__.co_argcount]
                # 3.9-compatible: zip(strict=) needs 3.10, tests run on system
                # pythons older than the container's 3.12.
                bound = dict(zip(names, args))  # noqa: B905
                bound.update(kwargs)
                self.audit(tool=tool, path=str(bound.get(path_arg, "")),
                           ok=False, error=error,
                           dry_run=bool(bound.get("dry_run")) or None)

            try:
                check_policy(tool)
                return fn(self, *args, **kwargs)
            except VaultError as exc:
                refuse(str(exc))
                raise
            except OSError as exc:
                refuse(f"os error: {exc}")
                raise VaultError(f"os error: {exc}") from exc

        return wrapper

    return deco


def split_frontmatter_raw(text: str):
    """Return (raw_frontmatter_block_or_None, body) without parsing YAML.

    A body-only edit must not touch the frontmatter at all. Round-tripping it
    through yaml.safe_load/safe_dump rewrites the WHOLE block: quotes vanish,
    `created: 2020-11-23T15:17:01` comes back as `2020-11-23 15:17:01` (YAML
    parsed it into a datetime and re-rendered it its own way), list indentation
    shifts, long strings refold. Nobody asked for any of that, and it lands in
    the note as a silent rewrite of the user's own metadata. The principle
    throughout: rewrite only what you own.
    """
    m = _FM_RE.match(text)
    if not m:
        return None, text
    return m.group(1), m.group(2)


def join_frontmatter_raw(fm: str | None, body: str) -> str:
    if fm is None:
        return body.lstrip("\n")
    return f"---\n{fm}\n---\n\n{body.lstrip(chr(10))}"


def set_fm_scalar(fm: str | None, key: str, value: str) -> str | None:
    """Set one scalar key in a RAW frontmatter block, leaving the rest alone.

    Replaces the key's line if it exists (top-level only, so a nested `title:`
    inside another mapping is not mistaken for the note's own), appends it
    otherwise. Returns None if there is no frontmatter to edit — creating one
    just to carry a key is a bigger decision than any caller here is making.
    """
    if fm is None:
        return None
    rendered = yaml.safe_dump({key: value}, allow_unicode=True,
                              default_flow_style=False).rstrip("\n")
    pat = re.compile(rf"^{re.escape(key)}:[^\n]*$", re.M)
    if pat.search(fm):
        return pat.sub(lambda _m: rendered, fm, count=1)
    return fm.rstrip("\n") + "\n" + rendered


class Vault:
    """All filesystem access for the MCP tools, confined to one vault root."""

    def __init__(self, root, inbox_rel: str = "00_Inbox/daily", tz=None,
                 log_dir=None, readonly: bool = False):
        self.root = Path(root).resolve()
        self.inbox_rel = (inbox_rel or "").strip("/")
        self.tz = tz or timezone.utc
        self.log_dir = Path(log_dir) if log_dir else None
        self.readonly = readonly

    # ── paths ────────────────────────────────────────────────────────────────

    def resolve(self, rel_path: str) -> Path:
        """Resolve a vault-relative path, refusing anything outside the vault."""
        p = (self.root / str(rel_path).lstrip("/")).resolve()
        if p != self.root and self.root not in p.parents:
            raise VaultError("path escapes the vault")
        if p.suffix.lower() != ".md":
            raise VaultError("only .md files are allowed")
        return p

    def rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def _posix(self, p: Path) -> str:
        return "/" + self.rel(p)

    def excluded(self, p: Path) -> bool:
        posix = self._posix(p)
        return any(part in posix for part in EXCLUDE_PARTS)

    def iter_notes(self, folder: str | None = None):
        base = self.root
        if folder:
            base = (self.root / folder.lstrip("/")).resolve()
            if base != self.root and self.root not in base.parents:
                raise VaultError("folder escapes the vault")
        for p in sorted(base.rglob("*.md")):
            # A symlink is a hole in the sandbox: rglob does not resolve it,
            # and reading through it would leak files outside the vault.
            if not p.is_symlink() and not self.excluded(p):
                yield p

    def iter_link_notes(self):
        """Every note a wikilink can live in (wider than iter_notes)."""
        for p in sorted(self.root.rglob("*.md")):
            if p.is_symlink():
                continue
            posix = self._posix(p)
            if not any(part in posix for part in LINK_SKIP_PARTS):
                yield p

    def read(self, p: Path) -> str:
        return p.read_text(encoding="utf-8")

    def note_hash(self, p: Path) -> str:
        return hash_text(self.read(p)) if p.is_file() else ""

    # ── write primitives ─────────────────────────────────────────────────────

    def _require_writable(self):
        if self.readonly:
            raise ReadOnly("server is read-only (MCP_READONLY)")

    def _existing(self, path: str) -> Path:
        p = self.resolve(path)
        if not p.is_file():
            raise NotFound(f"not found: {path}")
        return p

    def check_expected(self, p: Path, expected_hash: str):
        want = (expected_hash or "").strip().lower()
        if not want:
            return
        if len(want) < 8:
            raise VaultError("expected_hash: нужно минимум 8 символов")
        have = self.note_hash(p)
        if not have.startswith(want):
            raise Conflict(
                f"conflict: {self.rel(p)} изменился с момента чтения "
                f"(на диске {have[:16]}…, ожидалось {want[:16]}…). "
                "Перечитайте заметку и повторите правку."
            )

    def atomic_write(self, p: Path, text: str) -> bool:
        """Write via a temp file + os.replace. False when nothing changed.

        The temp name carries the pid AND a random suffix: requests run
        concurrently inside one process, and a per-pid name alone made two
        simultaneous writes to the same note share one temp file (three of
        four racing writers crashed, the survivor could commit the other's
        bytes). fsync before the rename so a power cut cannot surface the
        rename ahead of the data.
        """
        data = text.encode("utf-8")
        if p.is_file() and p.read_bytes() == data:
            return False
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.stem}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, p)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        return True

    def diff(self, old: str, new: str, rel: str) -> str:
        return "".join(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
            )
        )

    def audit(self, **fields):
        """Append one JSONL line per mutating call; never raises."""
        try:
            if self.log_dir is None:
                return
            rec = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
            user = CURRENT_USER.get()
            if user:
                rec["user"] = user
            auth = CURRENT_AUTH.get()
            if auth:
                rec["auth"] = auth
            for k, v in fields.items():
                if v not in ("", None):
                    rec[k] = v
            self.log_dir.mkdir(parents=True, exist_ok=True)
            with (self.log_dir / "mcp-writes.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001 — the journal must never break a call
            pass

    def _commit(self, tool: str, p: Path, new_text: str, *, dry_run: bool = False,
                extra: dict | None = None) -> str:
        """Shared tail of every write: diff-or-write, journal, formatted answer."""
        old = self.read(p) if p.is_file() else ""
        rel = self.rel(p)
        extra = {k: v for k, v in (extra or {}).items() if v not in ("", None)}
        if dry_run:
            self.audit(tool=tool, path=rel, ok=True, dry_run=True, **extra)
            body = self.diff(old, new_text, rel) or "(изменений нет)"
            return f"dry-run: {tool} {rel}\n{body}"

        changed = self.atomic_write(p, new_text)
        h = hash_text(new_text)
        self.audit(
            tool=tool, path=rel, ok=True,
            hash_before=hash_text(old) if old else "", hash_after=h,
            bytes_before=len(old.encode("utf-8")) if old else 0,
            bytes_after=len(new_text.encode("utf-8")),
            **extra,
        )
        tail = "" if changed else " (без изменений)"
        return f"ok: {tool} {rel} hash={h} bytes={len(new_text.encode('utf-8'))}{tail}"

    # ── frontmatter helpers for listings ─────────────────────────────────────

    @staticmethod
    def _fm_scalar(value) -> str:
        if isinstance(value, list):
            return ", ".join(str(x) for x in value)
        return "" if value is None else str(value)

    @staticmethod
    def _fm_matches(value, op: str, want: str) -> bool:
        want = want.strip().lower()
        if isinstance(value, list):
            have = [str(x).strip().lower() for x in value]
        else:
            have = [] if value is None else [str(value).strip().lower()]
        have = [h for h in have if h]
        if want == "*":
            found = bool(have)
        else:
            found = want in have
        return found if op == "=" else not found

    @staticmethod
    def _parse_where(where: str):
        conds = []
        for chunk in (where or "").split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "!=" in chunk:
                key, want = chunk.split("!=", 1)
                conds.append((key.strip(), "!=", want))
            elif "=" in chunk:
                key, want = chunk.split("=", 1)
                conds.append((key.strip(), "=", want))
            else:
                raise VaultError(f"where: не разобрал условие '{chunk}'")
        return conds

    def _fields_suffix(self, data, fields: list[str]) -> str:
        out = []
        for f in fields:
            if isinstance(data, dict) and f in data:
                out.append(f"{f}={self._fm_scalar(data[f])}")
        return ("" if not out else " | " + " | ".join(out))

    # ── read tools ───────────────────────────────────────────────────────────

    def list_notes(self, folder: str = "", limit: int = 200, fields: str = "",
                   where: str = "") -> str:
        want_fields = [f.strip() for f in (fields or "").split(",") if f.strip()]
        conds = self._parse_where(where)
        out = []
        for p in self.iter_notes(folder or None):
            suffix = ""
            if want_fields or conds:
                try:
                    data, _ = split_frontmatter(self.read(p))
                except (OSError, UnicodeDecodeError):
                    continue
                if conds:
                    data_d = data if isinstance(data, dict) else {}
                    if not all(
                        self._fm_matches(data_d.get(k), op, v) for k, op, v in conds
                    ):
                        continue
                suffix = self._fields_suffix(data, want_fields)
            out.append(self.rel(p) + suffix)
            if len(out) >= limit:
                break
        return "\n".join(out) if out else "(no notes)"

    def search_notes(self, query: str, limit: int = 30, fields: str = "") -> str:
        q = query.lower()
        want_fields = [f.strip() for f in (fields or "").split(",") if f.strip()]
        hits = []
        for p in self.iter_notes(None):
            try:
                text = self.read(p)
            except (OSError, UnicodeDecodeError):
                continue
            if q in text.lower():
                snippet = next(
                    (ln.strip() for ln in text.splitlines() if q in ln.lower()), ""
                )
                suffix = ""
                if want_fields:
                    data, _ = split_frontmatter(text)
                    suffix = self._fields_suffix(data, want_fields)
                hits.append(f"{self.rel(p)}{suffix}\n    {snippet[:200]}")
                if len(hits) >= limit:
                    break
        return "\n".join(hits) if hits else "(no matches)"

    def read_note(self, path: str) -> str:
        return self.read(self._existing(path))

    def note_info(self, path: str) -> str:
        p = self._existing(path)
        text = self.read(p)
        data, body = split_frontmatter(text)
        st = p.stat()
        lines = [
            f"path: {self.rel(p)}",
            f"bytes: {st.st_size}",
            f"mtime: {datetime.fromtimestamp(st.st_mtime, timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
            f"sha256: {hash_text(text)}",
        ]
        if isinstance(data, dict) and data:
            lines.append("frontmatter:")
            for k, v in data.items():
                lines.append(f"  {k}: {self._fm_scalar(v)}")
        blines = body.splitlines()
        headings = []
        for ln, fenced in zip(blines, fence_flags(blines)):  # noqa: B905
            if fenced:
                continue
            m = _HEADING_RE.match(ln)
            if m:
                headings.append(f"  {'#' * len(m.group(1))} {m.group(2)}")
        if headings:
            lines.append("headings:")
            lines.extend(headings)
        return "\n".join(lines)

    def search_by_tag(self, tag: str, limit: int = 100) -> str:
        t = tag.lstrip("#").strip().lower()
        if not t:
            raise VaultError("empty tag")
        hits = []
        for p in self.iter_notes(None):
            try:
                data, body = split_frontmatter(self.read(p))
            except (OSError, UnicodeDecodeError):
                continue
            tags = note_tags(data, body)
            if any(n == t or n.startswith(t + "/") for n in tags):
                hits.append(self.rel(p))
                if len(hits) >= limit:
                    break
        return "\n".join(hits) if hits else "(no notes)"

    def get_backlinks(self, path: str, limit: int = 100) -> str:
        target = self.resolve(path)
        name = target.stem.lower()
        rel_noext = self.rel(target)[:-3].lower()
        hits = []
        for p in self.iter_notes(None):
            if p == target:
                continue
            try:
                text = self.read(p)
            except (OSError, UnicodeDecodeError):
                continue
            for m in _WIKILINK_RE.finditer(text):
                tgt = m.group(1).strip().lower()
                if tgt.endswith(".md"):
                    tgt = tgt[:-3]
                if tgt == rel_noext or tgt.rsplit("/", 1)[-1] == name:
                    hits.append(self.rel(p))
                    break
            if len(hits) >= limit:
                break
        return "\n".join(hits) if hits else "(no backlinks)"

    # ── write tools ──────────────────────────────────────────────────────────

    @_journaled("create_note", path_arg="title")
    def create_note(self, title: str, content: str, folder: str = "",
                    dry_run: bool = False) -> str:
        self._require_writable()
        folder = (folder or "").strip("/") or self.inbox_rel
        now = datetime.now(self.tz)

        data, body = split_frontmatter(content)
        data = dict(data or {})
        data.setdefault("created", f"{now:%Y-%m-%d}")
        data.setdefault("source", "mcp")
        body = body.lstrip("\n")
        if not body.startswith("# "):
            body = f"# {title}\n\n{body}"

        # An inbox note is a temporary landing spot (a timestamp keeps drops
        # unique; microseconds, because two drops can land in the same
        # second). A note written straight into a folder is a permanent note
        # the user will LINK to, and `[[20260817-004216-…]]` is not a link
        # anybody writes — hence the title as the filename there.
        if folder == self.inbox_rel:
            rel = f"{folder}/{now:%Y%m%d-%H%M%S-%f}-{slugify(title)}.md"
        else:
            rel = f"{folder}/{filename(title)}.md"
        # Identity from birth: an `id:` derived from the birth path lets any
        # external index or cache key the note by it, so it survives every
        # later rename or move without a re-extraction.
        data.setdefault("id", note_id(rel))

        p = self.resolve(rel)
        if p.exists():
            raise VaultError(
                f"file exists: {self.rel(p)} — для перезаписи используйте write_note, "
                "для переименования rename_note"
            )
        return self._commit(
            "create_note", p,
            join_frontmatter(data, body.rstrip("\n") + "\n"),
            dry_run=dry_run,
        )

    @_journaled("write_note")
    def write_note(self, path: str, content: str, expected_hash: str = "",
                   dry_run: bool = False) -> str:
        self._require_writable()
        p = self._existing(path)
        self.check_expected(p, expected_hash)
        text = content if content.endswith("\n") else content + "\n"
        return self._commit("write_note", p, text, dry_run=dry_run)

    @_journaled("append_to_note")
    def append_to_note(self, path: str, content: str, expected_hash: str = "",
                       dry_run: bool = False) -> str:
        self._require_writable()
        p = self._existing(path)
        self.check_expected(p, expected_hash)
        old = self.read(p)
        sep = "" if content.startswith("\n") else "\n"
        return self._commit("append_to_note", p, old + sep + content + "\n",
                            dry_run=dry_run)

    @_journaled("patch_note")
    def patch_note(self, path: str, heading: str, content: str,
                   operation: str = "append", create_if_missing: bool = True,
                   expected_hash: str = "", dry_run: bool = False) -> str:
        self._require_writable()
        if operation not in ("append", "prepend", "replace"):
            raise VaultError("operation must be append, prepend or replace")
        p = self._existing(path)
        self.check_expected(p, expected_hash)

        fm, body = split_frontmatter_raw(self.read(p))
        lines = body.splitlines()
        found = find_section(lines, heading)

        if found is None:
            if not create_if_missing:
                raise NotFound(f"heading not found: {heading}")
            wanted = [h.strip() for h in heading.split("::") if h.strip()]
            block = body.rstrip("\n") + f"\n\n## {wanted[-1]}\n\n{content.strip()}\n"
            return self._commit("patch_note", p, join_frontmatter_raw(fm, block),
                                dry_run=dry_run, extra={"heading": heading})

        hi, _level, end = found
        start = hi + 1  # 0 for the preamble
        new_lines = content.split("\n")
        if operation == "prepend":
            lines[start:start] = new_lines
        elif operation == "replace":
            lines[start:end] = new_lines
        else:  # append: after the section body, trimming trailing blank lines
            tail = end
            while tail > start and not lines[tail - 1].strip():
                tail -= 1
            lines[tail:tail] = ([""] if tail > start else []) + new_lines

        return self._commit(
            "patch_note", p,
            join_frontmatter_raw(fm, "\n".join(lines) + "\n"),
            dry_run=dry_run, extra={"heading": heading or "(преамбула)"},
        )

    @_journaled("edit_frontmatter")
    def edit_frontmatter(self, field: str, path: str, value: str = "",
                         operation: str = "set", expected_hash: str = "",
                         dry_run: bool = False) -> str:
        self._require_writable()
        if operation not in ("set", "append", "delete"):
            raise VaultError("operation must be set, append or delete")
        p = self._existing(path)
        self.check_expected(p, expected_hash)

        data, body = split_frontmatter(self.read(p))
        data = data or {}
        # A canonical integer is typed BEFORE join_frontmatter, so safe_dump
        # prints it bare (tier: 2); everything else keeps the string behavior.
        typed = canonical_int(value)
        new = typed if typed is not None else value
        if operation == "delete":
            data.pop(field, None)
        elif operation == "append":
            cur = data.get(field)
            if cur is None:
                data[field] = [new]
            elif isinstance(cur, list):
                cur.append(new)
            else:
                data[field] = [cur, new]
        else:
            data[field] = new
        return self._commit("edit_frontmatter", p, join_frontmatter(data, body),
                            dry_run=dry_run, extra={"field": field})

    @_journaled("delete_section")
    def delete_section(self, path: str, heading: str, expected_hash: str = "",
                       dry_run: bool = False) -> str:
        self._require_writable()
        if not heading.strip():
            raise VaultError(
                "delete_section: пустой heading не поддержан — стереть преамбулу "
                "можно через patch_note с operation=replace"
            )
        p = self._existing(path)
        self.check_expected(p, expected_hash)

        fm, body = split_frontmatter_raw(self.read(p))
        lines = body.splitlines()
        found = find_section(lines, heading)
        if found is None:
            raise NotFound(f"heading not found: {heading}")
        hi, _level, end = found
        del lines[hi:end]
        # Collapse the blank-line run the removal left behind.
        while hi > 0 and hi < len(lines) and not lines[hi - 1].strip() and not lines[hi].strip():
            del lines[hi]
        return self._commit(
            "delete_section", p,
            join_frontmatter_raw(fm, "\n".join(lines).rstrip("\n") + "\n"),
            dry_run=dry_run, extra={"heading": heading},
        )

    @_journaled("delete_note")
    def delete_note(self, path: str, expected_hash: str = "",
                    permanent: bool = False, dry_run: bool = False) -> str:
        self._require_writable()
        p = self._existing(path)
        self.check_expected(p, expected_hash)
        rel = self.rel(p)
        text = self.read(p)

        if permanent:
            if dry_run:
                self.audit(tool="delete_note", path=rel, ok=True, dry_run=True,
                           permanent=True)
                return f"dry-run: delete_note {rel} (permanent)"
            p.unlink()
            self.audit(tool="delete_note", path=rel, ok=True, permanent=True,
                       hash_before=hash_text(text),
                       bytes_before=len(text.encode("utf-8")))
            return f"ok: delete_note {rel} permanent"

        # Microseconds in the stamp: two deletions in the same second must
        # not overwrite each other in the trash (the loop below stays as a
        # belt-and-suspenders for exotic filesystems with coarse timestamps).
        stamp = f"{datetime.now(self.tz):%Y%m%d-%H%M%S-%f}"
        trash = self.root / TRASH_REL
        target = trash / f"{stamp}-{p.name}"
        n = 1
        while target.exists():
            target = trash / f"{stamp}-{p.stem}-{n}.md"
            n += 1
        trash_rel = target.relative_to(self.root).as_posix()

        if dry_run:
            self.audit(tool="delete_note", path=rel, ok=True, dry_run=True,
                       trash_path=trash_rel)
            return f"dry-run: delete_note {rel} → {trash_rel}"

        trash.mkdir(parents=True, exist_ok=True)
        os.replace(p, target)
        self.audit(tool="delete_note", path=rel, ok=True, trash_path=trash_rel,
                   hash_before=hash_text(text),
                   bytes_before=len(text.encode("utf-8")))
        return f"ok: delete_note {rel} → {trash_rel}"

    @_journaled("rename_note")
    def rename_note(self, path: str, new_title: str, update_links: bool = True,
                    update_h1: bool = True, expected_hash: str = "",
                    dry_run: bool = False) -> str:
        self._require_writable()
        p = self._existing(path)
        self.check_expected(p, expected_hash)
        new_title = new_title.strip()
        if not new_title:
            raise VaultError("rename_note: new_title пустой")

        old_stem = p.stem
        new_stem = filename(new_title)
        target = p.with_name(f"{new_stem}.md")
        if target != p and target.exists():
            raise VaultError(f"file exists: {self.rel(target)}")

        # The note itself: title in frontmatter, H1 in the body.
        old_text = self.read(p)
        fm, body = split_frontmatter_raw(old_text)
        data, _ = split_frontmatter(old_text)
        if fm is not None:
            fm = set_fm_scalar(fm, "title", new_title)
            # Pin a stable identity BEFORE the path changes: anything that
            # keys data by the note (an index, a cache, a database) follows
            # the `id:` field instead of the file path, so the rename does not
            # orphan what was filed under the old path.
            if not str((data or {}).get("id") or "").strip():
                fm = set_fm_scalar(fm, "id", note_id(self.rel(p)))
        if update_h1:
            blines = body.splitlines()
            for i, (ln, fenced) in enumerate(zip(blines, fence_flags(blines))):  # noqa: B905
                if not fenced and ln.startswith("# "):
                    blines[i] = f"# {new_title}"
                    break
            body = "\n".join(blines) + ("\n" if body.endswith("\n") else "")
        self_text = join_frontmatter_raw(fm, body)

        # Incoming links everywhere else. Order matters: links first, the rename
        # last, so a crash leaves links pointing at the future name and a rerun
        # finishes the job (the reverse order would leave dangling links).
        touched: dict[Path, str] = {}
        if update_links and new_stem != old_stem:
            self_text = rewrite_links(self_text, old_stem, new_stem)
            for other in self.iter_link_notes():
                if other == p:
                    continue
                try:
                    text = self.read(other)
                except (OSError, UnicodeDecodeError):
                    continue
                if old_stem not in text:
                    continue
                fixed = rewrite_links(text, old_stem, new_stem)
                if fixed != text:
                    touched[other] = fixed

        rel_old, rel_new = self.rel(p), self.rel(target)
        if dry_run:
            self.audit(tool="rename_note", path=rel_old, ok=True, dry_run=True,
                       new_path=rel_new, links_in=len(touched))
            return (
                f"dry-run: rename_note {rel_old} → {rel_new}\n"
                f"ссылок будет переписано в заметках: {len(touched)}\n"
                + (self.diff(old_text, self_text, rel_old) or "(тело не меняется)")
            )

        for other, text in touched.items():
            self.atomic_write(other, text)
        self.atomic_write(p, self_text)
        if target != p:
            os.replace(p, target)
        self.audit(tool="rename_note", path=rel_old, ok=True, new_path=rel_new,
                   links_in=len(touched), hash_before=hash_text(old_text),
                   hash_after=hash_text(self_text))
        return (
            f"ok: rename_note {rel_old} → {rel_new} "
            f"hash={hash_text(self_text)} links_in={len(touched)}"
        )
