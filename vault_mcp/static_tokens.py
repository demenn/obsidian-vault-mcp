"""Static (pre-issued) bearer tokens for machine accounts of the MCP server.

A human signs in through OAuth; a machine cannot press "Allow", so it presents
a token issued in advance. This module owns the server side of that: a text
file of token HASHES (never the tokens) with an expiry date and a per-account
tool policy, re-read whenever it changes so that issuing, rotating and
revoking an account never needs a container restart.

Deliberately free of any fastmcp import, like ``vaultops.py``: CI has no
fastmcp, and everything here is meant to run in an offline test. ``server.py``
wraps :class:`StaticTokenStore` in a thin ``TokenVerifier``.

File format (``MCP_STATIC_TOKENS_FILE``), one account per line::

    # login  algo    hash(hex, sha256 of the raw token)           expires     policy
    agent    sha256  9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  2027-03-01  deny=delete_note,delete_section

``expires`` is the FIRST day (UTC) on which the token is no longer valid. The
optional ``policy`` is ``readonly`` (every mutating tool refused) or
``deny=<tool>[,<tool>...]`` (the listed mutating tools refused). A line that
does not parse is skipped and reported once per file version; the others keep
working. No file, or no valid line, means static login is OFF — nothing is
accepted (fail closed).

Contract: ``docs/static-tokens.md``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

log = logging.getLogger("mcp.static_tokens")

TOKEN_PREFIX = "ovm_"
# 32 random bytes, base64url without padding → 43 characters.
TOKEN_RE = re.compile(r"^ovm_[A-Za-z0-9_-]{43}$")
HASH_ALGO = "sha256"
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Sentinel inside a denied-set meaning "every mutating tool" (the readonly policy).
READONLY_ALL = "*"
POLICY_READONLY = "readonly"
POLICY_DENY_PREFIX = "deny="
FINGERPRINT_LEN = 12
AUTH_JOURNAL = "mcp-auth.jsonl"


class StaticTokenError(Exception):
    """Base for refusals; carries no token material."""


class UnknownToken(StaticTokenError):
    """No line matches: never issued, or revoked — the two are indistinguishable."""


class ExpiredToken(StaticTokenError):
    def __init__(self, login: str, expires: date):
        super().__init__(f"token of '{login}' expired on {expires.isoformat()}")
        self.login = login
        self.expires = expires


@dataclass(frozen=True)
class Entry:
    login: str
    digest: str            # lowercase hex sha256 of the raw token
    expires: date          # first day (UTC) the token is invalid
    denied: frozenset[str]  # tool names, or {READONLY_ALL}
    line_no: int

    @property
    def readonly(self) -> bool:
        return READONLY_ALL in self.denied

    @property
    def policy(self) -> str:
        if self.readonly:
            return POLICY_READONLY
        if self.denied:
            return POLICY_DENY_PREFIX + ",".join(sorted(self.denied))
        return ""

    def expires_at(self) -> int:
        """Unix seconds of the first invalid instant (midnight UTC of ``expires``)."""
        return int(datetime(self.expires.year, self.expires.month, self.expires.day,
                            tzinfo=timezone.utc).timestamp())

    def is_valid_at(self, now: datetime) -> bool:
        return now.astimezone(timezone.utc).date() < self.expires


# ── token material ───────────────────────────────────────────────────────────

def generate_token() -> str:
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return TOKEN_PREFIX + raw


def looks_like_ours(token: str) -> bool:
    """Prefix check only: decides whether a rejection is worth journaling."""
    return isinstance(token, str) and token.startswith(TOKEN_PREFIX)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def fingerprint(token: str) -> str:
    """Short, non-reversible handle for a token in logs (first 12 hex of sha256)."""
    return hash_token(token)[:FINGERPRINT_LEN]


# ── line format ──────────────────────────────────────────────────────────────

def parse_policy(text: str, known_tools: set[str] | frozenset[str] | None) -> frozenset[str]:
    """``readonly`` → {READONLY_ALL}; ``deny=a,b`` → {a, b}; anything else → ValueError.

    ``known_tools`` is the set of mutating tool names the server has; a policy
    naming anything else is a typo, and a typo must reject the LINE rather than
    silently grant more than intended.
    """
    text = (text or "").strip()
    if not text:
        return frozenset()
    if text == POLICY_READONLY:
        return frozenset({READONLY_ALL})
    if not text.startswith(POLICY_DENY_PREFIX):
        raise ValueError(f"unknown policy '{text}' (expected 'readonly' or 'deny=<tool>,…')")
    names = [n.strip() for n in text[len(POLICY_DENY_PREFIX):].split(",")]
    if not names or any(not n for n in names):
        raise ValueError("empty tool name in deny= policy")
    if known_tools is not None:
        bad = sorted(set(names) - set(known_tools))
        if bad:
            raise ValueError(
                f"deny= names unknown mutating tool(s) {bad}; known: {sorted(known_tools)}"
            )
    return frozenset(names)


def parse_expires(text: str) -> date:
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"bad expiry date '{text}' (expected YYYY-MM-DD)") from exc


def parse_line(line: str, line_no: int,
               known_tools: set[str] | frozenset[str] | None) -> Entry | None:
    """One line → Entry; ``None`` for blanks/comments; ValueError for a bad line.

    Error messages never contain the hash: they end up in the container log.
    """
    body = line.split("#", 1)[0].strip()
    if not body:
        return None
    fields = body.split()
    if len(fields) not in (4, 5):
        raise ValueError(f"line {line_no}: expected 4 or 5 fields, got {len(fields)}")
    login, algo, digest, expires = fields[:4]
    policy = fields[4] if len(fields) == 5 else ""
    if not LOGIN_RE.match(login):
        raise ValueError(f"line {line_no}: bad login")
    if algo != HASH_ALGO:
        raise ValueError(f"line {line_no}: unsupported hash algorithm '{algo}'")
    digest = digest.lower()
    if not HEX_RE.match(digest):
        raise ValueError(f"line {line_no}: hash is not 64 hex characters")
    try:
        exp = parse_expires(expires)
        denied = parse_policy(policy, known_tools)
    except ValueError as exc:
        raise ValueError(f"line {line_no}: {exc}") from exc
    return Entry(login=login.lower(), digest=digest, expires=exp, denied=denied,
                 line_no=line_no)


def parse_text(text: str,
               known_tools: set[str] | frozenset[str] | None) -> tuple[list[Entry], list[str]]:
    """Whole file → (entries, error messages). A bad line never sinks the rest."""
    entries: list[Entry] = []
    errors: list[str] = []
    for no, line in enumerate(text.splitlines(), start=1):
        try:
            e = parse_line(line, no, known_tools)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if e is not None:
            entries.append(e)
    return entries, errors


def format_line(login: str, digest: str, expires: date | str, policy: str = "") -> str:
    """Render a file line; the inverse of :func:`parse_line`."""
    exp = expires if isinstance(expires, str) else expires.isoformat()
    parts = [login, HASH_ALGO, digest, exp]
    if policy:
        parts.append(policy)
    return " ".join(parts)


# ── the store ────────────────────────────────────────────────────────────────

class StaticTokenStore:
    """The hash file, re-parsed only when its mtime or size changes.

    ``known_tools`` validates ``deny=`` policies; pass the server's mutating
    tool names (``vaultops.MUTATING_TOOLS``). ``reloads`` counts parses, so a
    test can prove an unchanged file is read once.
    """

    def __init__(self, path: str | Path | None,
                 known_tools: set[str] | frozenset[str] | None = None):
        self.path = Path(path) if path else None
        self.known_tools = frozenset(known_tools) if known_tools is not None else None
        self._sig: tuple[int, int] | None = None   # (mtime_ns, size) of the parsed file
        self._entries: list[Entry] = []
        self.errors: list[str] = []
        self.reloads = 0

    # -- state -----------------------------------------------------------------

    def _signature(self) -> tuple[int, int] | None:
        if self.path is None:
            return None
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:  # unreadable dir etc.: treat as absent, say so once
            log.warning("static tokens: cannot stat %s: %s", self.path, exc)
            return None
        return (st.st_mtime_ns, st.st_size)

    def refresh(self) -> None:
        sig = self._signature()
        if sig == self._sig:
            return
        self._sig = sig
        self.reloads += 1
        if sig is None:
            if self._entries:
                log.warning("static tokens: %s gone, static login disabled", self.path)
            self._entries, self.errors = [], []
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("static tokens: cannot read %s: %s", self.path, exc)
            self._entries, self.errors = [], [str(exc)]
            return
        self._entries, self.errors = parse_text(text, self.known_tools)
        for err in self.errors:
            log.warning("static tokens: %s skipped, %s", self.path, err)
        log.info("static tokens: %s loaded, %d account(s)%s", self.path,
                 len(self._entries), f", {len(self.errors)} bad line(s)" if self.errors else "")

    def entries(self) -> list[Entry]:
        self.refresh()
        return list(self._entries)

    @property
    def enabled(self) -> bool:
        return bool(self.entries())

    # -- verification ----------------------------------------------------------

    def lookup(self, token: str, now: datetime | None = None) -> Entry:
        """Return the matching, unexpired Entry or raise Unknown/ExpiredToken.

        Constant-time comparison against every line: the answer must not leak
        which hash prefix matched. The first matching line wins; if it is
        expired the token is expired (a rotated account has one line).
        """
        digest = hash_token(token)
        for e in self.entries():
            if hmac.compare_digest(digest, e.digest):
                if not e.is_valid_at(now or datetime.now(timezone.utc)):
                    raise ExpiredToken(e.login, e.expires)
                return e
        raise UnknownToken("token not in the static token file")


# ── rejection journal ────────────────────────────────────────────────────────

def journal_rejection(log_dir: str | Path | None, *, reason: str, token: str,
                      login: str = "") -> None:
    """One JSONL line per rejected static token; never raises.

    Only tokens with our prefix are journaled (the caller checks
    :func:`looks_like_ours`): a stale OAuth JWT also reaches the verifier after
    the provider refuses it, and without the filter the journal would be made
    of those. Successes are not journaled — one per agent request is noise.
    """
    try:
        if not log_dir:
            return
        rec = {
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "outcome": "rejected",
            "reason": reason,
        }
        if login:
            rec["login"] = login
        rec["fp"] = fingerprint(token)
        d = Path(log_dir)
        d.mkdir(parents=True, exist_ok=True)
        with (d / AUTH_JOURNAL).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001 — the journal must never break a request
        pass


class AccessDenied(Exception):
    """The caller is authenticated but may not use the server.

    Not a :class:`StaticTokenError`: those are about a TOKEN (unknown,
    expired) and are raised while verifying it; this one is about an
    IDENTITY, OAuth or static, and is raised after verification succeeded.
    """


def authorize(claims: dict, allowed: set[str] | frozenset[str],
              identity_claims: tuple[str, ...]) -> tuple[str, str, frozenset[str]]:
    """Who the caller is and whether they get in: ``(identity, auth, denied_tools)``.

    A static identity (claim ``auth: static``) skips the allow-list: its line
    in the hash file IS the allow-list of the machine account. An OAuth
    identity (first non-empty of ``identity_claims``) must be in ``allowed``,
    and an EMPTY allow-list admits nobody (fail closed — an empty
    ``MCP_ALLOWED_USERS`` must never switch the check off and open the vault
    to any GitHub/Google account).
    """
    if claims.get("auth") == "static":
        login = (claims.get("login") or "").lower()
        if not login:
            raise AccessDenied("access denied: static token without a login")
        return login, "static", frozenset(claims.get("deny") or ())
    identity = ""
    for claim in identity_claims:
        identity = (claims.get(claim) or "").lower()
        if identity:
            break
    if not allowed:
        raise AccessDenied("access denied: MCP_ALLOWED_USERS is empty, nobody is admitted")
    if identity not in allowed:
        raise AccessDenied(f"access denied: user '{identity or '?'}' is not authorized")
    return identity, "", frozenset()
