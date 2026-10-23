"""Obsidian vault MCP server.

A minimal, auditable Model Context Protocol server over an Obsidian vault —
plain markdown files on disk. Operates directly on the vault's files (no
headless Obsidian needed), so it stays light and the tool surface is fully
owned and reviewable instead of trusting a third-party server with read/write
access to a personal vault.

Transport: streamable HTTP (required by Claude remote connectors), served at
``/mcp/``. Built on PrefectHQ FastMCP so OAuth is handled in-process.

Auth (provider selected by MCP_AUTH_PROVIDER: "github" default, or "google"):
  - OAuth (FastMCP ``GitHubProvider`` / ``GoogleProvider``) provides
    authentication. A logged-in account alone only proves *some* account, so a
    second layer — ``AllowListMiddleware`` — enforces *authorization*: only
    identities in MCP_ALLOWED_USERS (GitHub logins / Google emails; legacy
    alias MCP_ALLOWED_GITHUB_USERS still works) may call the server, and an
    EMPTY list admits nobody (fail closed). The identity claim
    only exists if the upstream token was granted the scope that carries it,
    hence the explicit Google email scope in ``_build_auth``.
  - ``allowed_client_redirect_uris`` restricts which MCP clients (Claude /
    localhost) may complete the OAuth dance (defense in depth on the client side).
  - A persistent ``jwt_signing_key`` keeps issued client tokens valid across
    restarts so the connector does not re-auth on every redeploy (the token
    store itself lives on a volume — see ``docker-compose.yml``).
  - ``GITHUB_TOKEN_CACHE_TTL`` bounds how often GitHub is asked to re-validate
    an already-verified token; see the constant for why the default matters.
  If the provider's client id is unset the server starts unauthenticated —
  only safe on an internal network (used for local/initialize smoke tests).

Tools:
  reading
  - list_notes        list markdown files (optionally a subfolder, + frontmatter)
  - search_notes      substring search across notes, returns path + snippet
  - read_note         read one note's content
  - note_info         size / mtime / sha256 / frontmatter / heading outline
  - search_by_tag     find notes tagged with a tag (frontmatter or inline #tag)
  - get_backlinks     find notes that link to a given note via [[wikilinks]]
  writing
  - create_note       create a NEW note (fails if the path is taken)
  - write_note        overwrite an existing note wholesale
  - append_to_note    append text to an existing note
  - patch_note        insert/replace under a heading, or before the first one
  - edit_frontmatter  set / append-to / delete a YAML frontmatter field
  - delete_section    remove a heading together with its body
  - delete_note       move a note to <vault>/.trash/ (or unlink with permanent)
  - rename_note       rename a note and repoint every incoming wikilink
  other
  - youtube_transcript  fetch a YouTube video's transcript + metadata (the
                        client summarizes it and saves via create_note) —
                        server-side so it works from the phone apps too

Every write is atomic (temp file + os.replace), skips the write entirely when
nothing changed, takes an optional ``expected_hash`` that refuses to overwrite a
note somebody else touched, supports ``dry_run`` (returns a diff, writes
nothing) and lands one JSONL line in ``${MCP_LOG_DIR}/mcp-writes.jsonl``. The
full contract and the reasoning behind it: ``docs/write-contract.md``.
The filesystem side lives in ``vaultops.py`` — this module is auth plus thin
tool wrappers, so the vault logic can be tested without fastmcp.

These deliberately replicate the useful parts of the Obsidian Local REST API
(structural patch, frontmatter edits, tag/backlink queries) at the filesystem
level, so we keep the rich tool surface without running a headless Obsidian.

Every path argument is resolved and confined to the vault; only .md files are
touched. Writes land in the synced vault → your sync (Obsidian Sync, Syncthing,
git…) propagates them to every device.
"""
from __future__ import annotations

import logging
import os
import re
from zoneinfo import ZoneInfo

from fastmcp import FastMCP
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.auth import AccessToken, MultiAuth, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext

from . import static_tokens
from .vaultops import (
    CURRENT_AUTH,
    CURRENT_DENIED_TOOLS,
    CURRENT_USER,
    MUTATING_TOOLS,
    Vault,
    VaultError,
)

VAULT = os.environ.get("VAULT_PATH", "/vault")
INBOX_REL = os.environ.get("VAULT_INBOX_REL", "Inbox")
TZ = ZoneInfo(os.environ.get("TZ", "UTC"))
LOG_DIR = os.environ.get("MCP_LOG_DIR", "/logs")
READONLY = (os.environ.get("MCP_READONLY", "") or "").strip().lower() in (
    "1", "true", "yes", "on",
)
# Hash file of pre-issued machine-account tokens (docs/static-tokens.md).
# Empty = no static login at all. Set but missing file = static login off until
# the file appears; it is re-read whenever it changes, never at startup only.
STATIC_TOKENS_FILE = os.environ.get("MCP_STATIC_TOKENS_FILE", "").strip()

# FastMCP configures only its own logger; without a root handler the static
# token module's "line 3 skipped" warnings would go nowhere.
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

# What we ask Google for, in the canonical URI form Google echoes back in the
# granted scope (the "email" shorthand is only accepted on the way in).
GOOGLE_UPSTREAM_SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
)

# How long a verified GitHub token stays trusted without re-asking GitHub.
# GitHub tokens are opaque, so FastMCP validates them by calling
# api.github.com/user — and with its default (caching OFF) that call happens on
# EVERY MCP request, twice. Any non-200 there — a rate-limit 403, a proxy
# hiccup, a timeout — is indistinguishable from a revoked token to the
# verifier, so the client is told its session expired and the connector drops
# into a re-auth loop (a real failure mode: OAuth succeeds, the first requests
# work, then every call returns invalid_token). Google needs no equivalent:
# its tokens are verified locally against JWKS.
GITHUB_TOKEN_CACHE_TTL = int(os.environ.get("MCP_GITHUB_TOKEN_CACHE_TTL", "300"))


def _build_auth():
    """Build the OAuth provider for MCP_AUTH_PROVIDER (github|google).

    Returns (provider_or_None, identity_claims) where identity_claims are the
    access-token claim names checked against the allow-list. None provider =
    internal (unauthenticated) mode.
    """
    provider = (os.environ.get("MCP_AUTH_PROVIDER") or "github").strip().lower()
    base_url = os.environ.get("MCP_BASE_URL", "").strip()

    # MCP client loopback redirects we trust (Claude web/desktop). The upstream
    # provider callback is base_url + redirect_path and is configured separately.
    allowed_redirects = [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
        "http://localhost:*",
        "http://127.0.0.1:*",
    ]
    kwargs = dict(
        base_url=base_url,
        redirect_path=os.environ.get("MCP_REDIRECT_PATH", "/auth/callback"),
        allowed_client_redirect_uris=allowed_redirects,
    )
    signing_key = os.environ.get("MCP_JWT_SIGNING_KEY", "").strip()
    if signing_key:
        kwargs["jwt_signing_key"] = signing_key

    if provider == "google":
        client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        if not (client_id and client_secret and base_url):
            return None, ()
        from fastmcp.server.auth.providers.google import GoogleProvider

        # GoogleProvider defaults to the bare "openid" scope, which yields a
        # token with no email claim — the allow-list would then see an anonymous
        # user and deny everyone. Asking for email in two places is deliberate:
        # required_scopes advertises it (a client picks its request out of
        # scopes_supported) and verifies the granted token carries it, while the
        # extra authorize param pins the scope we send Google even when a client
        # asks for less — Claude's CIMD document declares no scopes at all.
        return (
            GoogleProvider(
                client_id=client_id,
                client_secret=client_secret,
                required_scopes=["openid", "email"],
                extra_authorize_params={"scope": " ".join(GOOGLE_UPSTREAM_SCOPES)},
                **kwargs,
            ),
            ("email",),
        )

    client_id = os.environ.get("GITHUB_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "").strip()
    if not (client_id and client_secret and base_url):
        return None, ()
    from fastmcp.server.auth.providers.github import GitHubProvider

    return (
        GitHubProvider(
            client_id=client_id,
            client_secret=client_secret,
            cache_ttl_seconds=GITHUB_TOKEN_CACHE_TTL,
            **kwargs,
        ),
        ("login",),
    )


class StaticTokenVerifier(TokenVerifier):
    """Second leg of ``MultiAuth``: a pre-issued token of a machine account.

    ``MultiAuth`` asks the OAuth provider first; a token it did not issue comes
    back ``None`` without a GitHub round-trip, and lands here. We answer only
    for tokens with our prefix, so the provider's stale JWTs do not pollute the
    rejection journal. Any exception here is swallowed by ``MultiAuth`` at
    debug level, hence the blanket catch: a broken hash file must be visible.
    """

    def __init__(self, store: static_tokens.StaticTokenStore, log_dir: str,
                 scopes: list[str] | None = None):
        super().__init__()
        self.store = store
        self.log_dir = log_dir
        # The bearer layer checks every AccessToken against the provider's
        # required_scopes (GitHubProvider: ["user"]) and answers 403
        # insufficient_scope otherwise — found on the first prod probe. A static
        # token has no OAuth scopes of its own, so it is minted with exactly the
        # scopes the provider requires; authorization is the hash line, not scopes.
        self.scopes = list(scopes or [])

    async def verify_token(self, token: str) -> AccessToken | None:
        if not static_tokens.looks_like_ours(token):
            return None
        try:
            entry = self.store.lookup(token)
        except static_tokens.ExpiredToken as exc:
            static_tokens.journal_rejection(self.log_dir, reason="expired", token=token,
                                            login=exc.login)
            logging.getLogger("mcp.auth").warning(
                "static token of '%s' rejected: expired on %s", exc.login, exc.expires)
            return None
        except static_tokens.UnknownToken:
            static_tokens.journal_rejection(self.log_dir, reason="unknown", token=token)
            logging.getLogger("mcp.auth").warning(
                "static token rejected: unknown (fp %s)", static_tokens.fingerprint(token))
            return None
        except Exception as exc:  # noqa: BLE001 — see docstring
            logging.getLogger("mcp.auth").error("static token check failed: %s", exc)
            return None
        return AccessToken(
            token=token,
            client_id=entry.login,
            scopes=self.scopes,
            expires_at=entry.expires_at(),
            claims={"login": entry.login, "auth": "static", "deny": sorted(entry.denied)},
        )


class AllowListMiddleware(Middleware):
    """Authorization layer: only allow-listed identities may use the server.

    The OAuth provider authenticates the caller and stows the identity in the
    access-token claims (GitHub: ``login``; Google: ``email``). FastMCP
    guarantees a valid token before any MCP request reaches middleware, so we
    just hand the claims to ``static_tokens.authorize``: the decision and its
    reasons live there, fastmcp-free, so the offline test can exercise it.

    It also parks the identity in ``vaultops.CURRENT_USER`` for the duration of
    the request: the write journal has to be able to answer "who deleted this",
    and this is the only place that has already resolved the claim. The
    account's tool policy travels the same way (``CURRENT_DENIED_TOOLS``).
    """

    def __init__(self, allowed: set[str], claims: tuple[str, ...]):
        self.allowed = allowed
        self.claims = claims

    async def on_request(self, context: MiddlewareContext, call_next):
        try:
            token = get_access_token()
        except Exception:  # noqa: BLE001 — unauthenticated mode has no token
            token = None
        claims = (token.claims if token else None) or {}
        try:
            identity, auth, denied = static_tokens.authorize(claims, self.allowed, self.claims)
        except static_tokens.AccessDenied as exc:
            raise AuthorizationError(str(exc)) from None
        r_user = CURRENT_USER.set(identity)
        r_auth = CURRENT_AUTH.set(auth)
        r_denied = CURRENT_DENIED_TOOLS.set(denied)
        try:
            return await call_next(context)
        finally:
            CURRENT_DENIED_TOOLS.reset(r_denied)
            CURRENT_AUTH.reset(r_auth)
            CURRENT_USER.reset(r_user)


_AUTH, _IDENTITY_CLAIMS = _build_auth()
if STATIC_TOKENS_FILE:
    if _AUTH is None:
        # Internal (unauthenticated) mode has no bearer layer to hang a second
        # verifier on; say so instead of silently ignoring the setting.
        logging.getLogger("mcp.auth").warning(
            "MCP_STATIC_TOKENS_FILE is set but no OAuth provider is configured; "
            "static login needs the auth layer and is OFF")
    else:
        _STORE = static_tokens.StaticTokenStore(STATIC_TOKENS_FILE, known_tools=MUTATING_TOOLS)
        # MultiAuth keeps every OAuth route and discovery document on the
        # provider and only widens verify_token: provider first, then ours.
        _VERIFIER = StaticTokenVerifier(
            _STORE, LOG_DIR, scopes=list(getattr(_AUTH, "required_scopes", None) or []))
        _AUTH = MultiAuth(server=_AUTH, verifiers=[_VERIFIER])
# MCP_ALLOWED_USERS is the generic knob (GitHub logins or Google emails);
# MCP_ALLOWED_GITHUB_USERS kept as a back-compat alias.
_ALLOWED = {
    u.strip().lower()
    for u in (
        os.environ.get("MCP_ALLOWED_USERS", "")
        or os.environ.get("MCP_ALLOWED_GITHUB_USERS", "")
    ).split(",")
    if u.strip()
}

mcp = FastMCP("obsidian-vault", auth=_AUTH)
if _AUTH is not None:
    if not _ALLOWED:
        # Fail closed, loudly: the server still starts (a static machine
        # account needs no allow-list), but no OAuth login gets in.
        logging.getLogger("mcp.auth").error(
            "MCP_ALLOWED_USERS (alias MCP_ALLOWED_GITHUB_USERS) is empty: every OAuth "
            "login will be refused; only static tokens (MCP_STATIC_TOKENS_FILE) can "
            "reach the vault")
    mcp.add_middleware(AllowListMiddleware(_ALLOWED, _IDENTITY_CLAIMS))

V = Vault(VAULT, inbox_rel=INBOX_REL, tz=TZ, log_dir=LOG_DIR, readonly=READONLY)


def _err(exc: Exception) -> str:
    """One shape for every refusal, so it cannot be mistaken for content."""
    return f"ERROR: {exc}"


@mcp.tool
def list_notes(folder: str = "", limit: int = 200, fields: str = "",
               where: str = "") -> str:
    """List markdown notes in the vault, optionally under a subfolder.

    Args:
        folder: vault-relative subfolder (e.g. "10_Notes/projects"); empty = whole vault.
        limit: max number of paths to return.
        fields: comma-separated frontmatter keys to show next to each path
            (e.g. "status,space") — answers "which tasks are open" without
            reading every file.
        where: comma-separated filter over frontmatter, ANDed together:
            "status=next", "status!=complete", "space=*" (field present).
            Matching is case-insensitive; for list fields (tags) an element
            must match.
    """
    try:
        return V.list_notes(folder, limit, fields, where)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def search_notes(query: str, limit: int = 30, fields: str = "") -> str:
    """Case-insensitive substring search across note contents.

    Returns matching notes with the first matching line as a snippet.
    `fields` adds frontmatter values next to each path, as in list_notes.
    """
    try:
        return V.search_notes(query, limit, fields)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def read_note(path: str) -> str:
    """Read the full content of a vault note (vault-relative .md path)."""
    try:
        return V.read_note(path)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def note_info(path: str) -> str:
    """Metadata of a note without pulling its body into the context.

    Returns path, size, mtime, sha256, frontmatter fields and the heading
    outline. The sha256 is what `expected_hash` expects: read it here, pass it
    to a write, and the write refuses if somebody changed the note meanwhile.
    """
    try:
        return V.note_info(path)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def create_note(title: str, content: str, folder: str = "",
                dry_run: bool = False) -> str:
    """Create a NEW note.

    By default the note is placed in the inbox — one known landing spot before
    you file it properly. Pass `folder` to write elsewhere in the vault.
    Returns the created vault-relative path and its hash.

    An existing path is an ERROR, never a silent duplicate: use write_note to
    overwrite, rename_note to rename.

    `content` may be either a bare body or a COMPLETE markdown document — an
    already-exported note with its own frontmatter and H1. That case is not
    hypothetical: it is what "put these files in the vault" means, and wrapping
    it in a second frontmatter block leaves Obsidian reading only the outer one
    while `title`/`category`/`tags` of the real document sit in the body as
    text, invisible to property search and Bases. So an incoming frontmatter is
    MERGED — its own keys win, ours only fill what it lacks — and an H1 the
    document already carries is not duplicated.
    """
    try:
        return V.create_note(title, content, folder, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def write_note(path: str, content: str, expected_hash: str = "",
               dry_run: bool = False) -> str:
    """Overwrite an EXISTING note wholesale with `content`.

    Content is written as given: no frontmatter merging, no H1 added — the tool
    is called "overwrite". Creating is create_note's job.

    Args:
        path: vault-relative .md path; must exist.
        content: the complete new document.
        expected_hash: sha256 (or its first 8+ chars) from note_info/an earlier
            write. If the file on disk no longer matches, the write is refused
            instead of silently discarding somebody else's edit.
        dry_run: return a unified diff and write nothing.
    """
    try:
        return V.write_note(path, content, expected_hash, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def append_to_note(path: str, content: str, expected_hash: str = "",
                   dry_run: bool = False) -> str:
    """Append text to the end of an existing vault note."""
    try:
        return V.append_to_note(path, content, expected_hash, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def patch_note(
    path: str,
    heading: str,
    content: str,
    operation: str = "append",
    create_if_missing: bool = True,
    expected_hash: str = "",
    dry_run: bool = False,
) -> str:
    """Surgically edit one section of a note (no full rewrite).

    Mirrors the Obsidian Local REST API PATCH-by-heading behaviour.

    Args:
        path: vault-relative .md path.
        heading: exact heading text WITHOUT leading '#'s (e.g. "См. также").
            For a nested heading use
            "::" between levels (e.g. "Проект::Задачи").
            EMPTY heading addresses the PREAMBLE — the region between the
            frontmatter and the first heading. That is how you put a block at
            the very top of a note, above the H1.
        content: text to insert.
        operation: "append" (after the section's existing body), "prepend"
            (right after the heading line; for the preamble: right after the
            frontmatter, above the H1), or "replace" (replace the body).
        create_if_missing: if the heading is absent, append a new "## heading"
            section at the end of the note instead of failing. Ignored for the
            preamble, which always exists.
        expected_hash: refuse the write if the note changed since you read it.
        dry_run: return a unified diff and write nothing.
    """
    try:
        return V.patch_note(path, heading, content, operation, create_if_missing,
                            expected_hash, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def edit_frontmatter(field: str, path: str, value: str = "",
                     operation: str = "set", expected_hash: str = "",
                     dry_run: bool = False) -> str:
    """Set, append-to, or delete a YAML frontmatter field of a note.

    Args:
        field: frontmatter key (e.g. "status", "tags").
        path: vault-relative .md path.
        value: value to set/append (ignored for delete). A canonical integer
            ("42", "-7": int(value) prints back unchanged) is stored as a
            number and written unquoted (tier: 2); any other value is stored
            as a string and quoted as before.
        operation: "set" (create/replace the field), "append" (treat the field
            as a list and add value), or "delete" (remove the field).
        expected_hash: refuse the write if the note changed since you read it.
        dry_run: return a unified diff and write nothing.
    """
    try:
        return V.edit_frontmatter(field, path, value, operation, expected_hash,
                                  dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def delete_section(path: str, heading: str, expected_hash: str = "",
                   dry_run: bool = False) -> str:
    """Remove a section — the heading line AND its body.

    The section ends at the next heading of the same or higher level, so nested
    subheadings go with their parent. Use this instead of patching a section
    with empty content, which leaves the bare heading behind.
    """
    try:
        return V.delete_section(path, heading, expected_hash, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def delete_note(path: str, expected_hash: str = "", permanent: bool = False,
                dry_run: bool = False) -> str:
    """Delete a note.

    By default the file MOVES to <vault>/.trash/<timestamp>-<name>.md: it leaves
    search and listings but stays recoverable by hand. `permanent=True` unlinks
    it for real. Incoming [[wikilinks]] are deliberately left alone — a broken
    link is visible and fixable, mass-editing other people's notes is not
    reversible.
    """
    try:
        return V.delete_note(path, expected_hash, permanent, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def rename_note(path: str, new_title: str, update_links: bool = True,
                update_h1: bool = True, expected_hash: str = "",
                dry_run: bool = False) -> str:
    """Rename a note and repoint every incoming wikilink at the new name.

    Obsidian resolves a link by FILENAME (not by `title`, not by `aliases`), so
    renaming without rewriting links breaks every reference, including the card
    on a kanban board. This rewrites [[old]], [[old|alias]], [[old#heading]],
    [[folder/old]] and the escaped [[old\\|alias]] form used inside tables, plus
    frontmatter scalars and quoted "folder/old.md" paths, across the whole vault.

    Args:
        path: vault-relative .md path of the note to rename.
        new_title: the new human title; the filename is derived from it.
        update_links: rewrite incoming references (leave on unless you know why).
        update_h1: also rewrite the note's own H1 line.
        dry_run: report what would change and write nothing.
    """
    try:
        return V.rename_note(path, new_title, update_links, update_h1,
                             expected_hash, dry_run)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def search_by_tag(tag: str, limit: int = 100) -> str:
    """List notes tagged with `tag` (frontmatter `tags:` or inline #tag).

    Case-insensitive; a leading '#' is optional. Matches the tag itself and any
    nested child tag (searching "tech" also matches "tech/ai").
    """
    try:
        return V.search_by_tag(tag, limit)
    except VaultError as exc:
        return _err(exc)


@mcp.tool
def get_backlinks(path: str, limit: int = 100) -> str:
    """List notes that link to the given note via [[wikilinks]].

    Matches Obsidian link forms — [[Name]], [[Name|alias]], [[Name#heading]],
    and [[folder/Name]] — by the note's filename or its vault-relative path.
    """
    try:
        return V.get_backlinks(path, limit)
    except VaultError as exc:
        return _err(exc)


# ── YouTube transcripts ──────────────────────────────────────────────────────
# Server-side on purpose: a local stdio MCP would only work on one machine,
# while this tool is reachable from phone apps through the same remote
# connector. Egress honors HTTPS_PROXY if set — youtube-transcript-api uses
# requests, which reads it.

_YT_ID_RE = re.compile(r"^[\w-]{11}$")


def _youtube_id(url: str) -> str | None:
    url = url.strip()
    if _YT_ID_RE.match(url):
        return url
    m = re.search(
        r"(?:youtu\.be/|youtube\.com/(?:watch\?[^#]*v=|shorts/|live/|embed/))"
        r"([\w-]{11})",
        url,
    )
    return m.group(1) if m else None


def _youtube_meta(video_id: str) -> dict:
    """Title/channel via the keyless oEmbed endpoint; empty dict on failure."""
    import json
    import urllib.parse
    import urllib.request

    q = urllib.parse.urlencode(
        {"url": f"https://www.youtube.com/watch?v={video_id}", "format": "json"}
    )
    try:
        with urllib.request.urlopen(
            f"https://www.youtube.com/oembed?{q}", timeout=15
        ) as resp:
            return json.load(resp)
    except Exception:
        return {}


@mcp.tool
def youtube_transcript(url: str, languages: str = "ru,en,de",
                       max_chars: int = 80000) -> str:
    """Fetch the transcript of a YouTube video (plus title/channel).

    Use this when the user shares a YouTube link and wants a summary or wants
    to work with the video's content. Summarize the returned text yourself,
    then (if asked to save) write the summary into the vault via create_note.

    Args:
        url: YouTube URL (watch/shorts/live/youtu.be) or a bare 11-char video id.
        languages: comma-separated preference order for transcript language
            (auto-generated transcripts are used when nothing better exists).
        max_chars: truncate the transcript beyond this length.
    """
    from youtube_transcript_api import YouTubeTranscriptApi
    from youtube_transcript_api._errors import (
        NoTranscriptFound,
        TranscriptsDisabled,
        VideoUnavailable,
    )

    video_id = _youtube_id(url)
    if not video_id:
        return "(не удалось распознать ссылку на YouTube — нужен URL вида youtube.com/watch?v=… или youtu.be/…)"

    prefs = [ln.strip() for ln in languages.split(",") if ln.strip()] or ["ru", "en"]
    api = YouTubeTranscriptApi()
    try:
        try:
            fetched = api.fetch(video_id, languages=prefs)
        except NoTranscriptFound:
            # Fall back to whatever language exists (incl. auto-generated).
            available = api.list(video_id)
            fetched = next(iter(available)).fetch()
    except TranscriptsDisabled:
        return f"(у видео {video_id} отключены субтитры — транскрипта нет)"
    except VideoUnavailable:
        return f"(видео {video_id} недоступно — удалено, приватное или регион-блок)"
    except Exception as exc:  # noqa: BLE001 — surface a readable reason
        return (
            f"(не удалось получить транскрипт {video_id}: {type(exc).__name__}: {exc}. "
            "Возможно, YouTube ограничил доступ с сервера — попробуйте позже)"
        )

    text = " ".join(
        snippet.text.replace("\n", " ").strip() for snippet in fetched
    ).strip()
    truncated = len(text) > max_chars
    if truncated:
        text = text[:max_chars]

    meta = _youtube_meta(video_id)
    header = [
        f"video: https://www.youtube.com/watch?v={video_id}",
        f"title: {meta.get('title', '(неизвестно)')}",
        f"channel: {meta.get('author_name', '(неизвестно)')}",
        f"language: {getattr(fetched, 'language_code', '?')}",
    ]
    if truncated:
        header.append(f"note: транскрипт обрезан до {max_chars} символов")
    return "\n".join(header) + "\n\n" + text


def main() -> None:
    """Run the HTTP server (container CMD and ``python -m vault_mcp``).

    Binds to 127.0.0.1 by default: without OAuth keys the server runs
    unauthenticated, and that must not quietly expose the vault to the whole
    local network. The container overrides this with MCP_HOST=0.0.0.0 behind
    its reverse proxy.
    """
    mcp.run(
        transport="http",
        host=os.environ.get("MCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("MCP_PORT", "8000")),
    )


if __name__ == "__main__":
    main()
