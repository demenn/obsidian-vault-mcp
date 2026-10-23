"""Filesystem-safe note naming (cross-platform: macOS/APFS ↔ Linux/ext4).

A note's filename doubles as its wikilink target. macOS/APFS allows up to 255
UTF-16 code units per filename, but Linux/ext4 caps a single name component at
**255 bytes** (NAME_MAX). Cyrillic is 2 bytes/char in UTF-8, so long titles
overflow when the vault is hosted on a Linux server.

`safe_stem()` keeps filenames within a conservative byte budget so the vault
is portable to Linux. When a title is too long, the stem is truncated on a
character boundary and a short stable hash is appended for uniqueness, using
the `(hash)` suffix convention (parentheses, NOT a `[hash]` square-bracket
form, which is wikilink-hostile).

The FULL title always survives in frontmatter (`title:`), so only the on-disk
filename of over-long outliers changes.
"""
from __future__ import annotations

import hashlib
import re

# ext4 caps a filename *component* at 255 bytes. A note file is "<stem>.md",
# so the stem must fit in 255 - len(".md") = 252 bytes. We keep a small extra
# margin for a rare " (2)" disambiguation suffix, so only genuinely-overflowing
# names get shortened (minimal churn: almost every note keeps filename==title).
MAX_STEM_BYTES = 245

# Illegal in a filename on some OS, or (`#` and `^`) legal on disk but not in
# a wikilink: Obsidian reads `[[Note#X]]` as a heading reference and `[[Note^X]]`
# as a block reference, so a file whose NAME holds one cannot be linked at all.
# The filename is this vault's link target, so both classes are folded here.
# `[` and `]` are folded for the same reason: a `]` in a stem breaks the
# alias-less form `"[[Name [hash]]]"`, which is the only form a frontmatter
# property link can take (Obsidian closes at the first `]]`).
_ILLEGAL_RE = re.compile(r'[\\/:*?"<>|#^\[\]]')
_WS_RE = re.compile(r"\s+")


def note_id(rel_path: str) -> str:
    """A note's identity: `sha1(path relative to the vault)[:12]`.

    Stamped into frontmatter `id:` when a note is born (e.g. by the MCP
    server's `create_note`) and backfilled for older notes; anything keying
    data by the note (an index, a cache, a database) follows it, so a rename
    or move never orphans the record. Takes the vault-relative POSIX path
    INCLUDING `.md`."""
    return hashlib.sha1(rel_path.encode("utf-8")).hexdigest()[:12]


def safe_filename(s: str) -> str:
    """Sanitize a title into a filename component (illegal chars -> _),
    collapsing whitespace. Does NOT enforce a length limit."""
    s = _ILLEGAL_RE.sub("_", s)
    return _WS_RE.sub(" ", s).strip()


def _byte_len(s: str) -> int:
    return len(s.encode("utf-8"))


def safe_stem(title: str, max_bytes: int = MAX_STEM_BYTES) -> str:
    """Filesystem-safe note stem within `max_bytes` UTF-8 bytes.

    Short titles pass through `safe_filename` unchanged. Over-long titles are
    truncated on a UTF-8 character boundary with a ` (<hash>)` suffix appended
    for uniqueness."""
    base = safe_filename(title)
    if _byte_len(base) <= max_bytes:
        return base
    digest = hashlib.sha1(title.encode("utf-8")).hexdigest()[:8]
    suffix = f" ({digest})"
    budget = max_bytes - _byte_len(suffix)
    truncated = base.encode("utf-8")[:budget].decode("utf-8", "ignore").rstrip()
    return f"{truncated}{suffix}"
