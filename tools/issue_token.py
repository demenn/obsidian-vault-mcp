#!/usr/bin/env python3
"""Issue a static token for a machine account of the vault MCP server.

The token itself is NEVER printed. It goes into a file with mode 0600
(``--out``) or into the macOS Keychain (``--keychain``); stdout carries only the
line for the server's hash file. Run it yourself, not from an agent session:
a secret that has been shown once is compromised for good.

    python tools/issue_token.py --login agent --expires 2027-03-01 \
        --deny delete_note,delete_section --keychain vault-mcp
    # → agent sha256 <64 hex> 2027-03-01 deny=delete_note,delete_section

Then append that line to the file named by MCP_STATIC_TOKENS_FILE on the
server; it takes effect on the next request. To re-hash a token you already
have (e.g. to add a policy): ``--hash-only --from-file <path>``.

Contract: docs/static-tokens.md.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from vault_mcp import (  # noqa: E402
    static_tokens,
    vaultops,  # for MUTATING_TOOLS (filled at import)
)


def build_policy(deny: str | None, readonly: bool) -> str:
    """CLI flags → the policy field, validated against the server's tool names."""
    if deny and readonly:
        raise SystemExit("ERROR: --deny and --readonly are mutually exclusive")
    if readonly:
        return static_tokens.POLICY_READONLY
    if deny:
        text = static_tokens.POLICY_DENY_PREFIX + ",".join(
            n.strip() for n in deny.split(",") if n.strip())
        try:
            static_tokens.parse_policy(text, vaultops.MUTATING_TOOLS)
        except ValueError as exc:
            raise SystemExit(f"ERROR: {exc}") from exc
        return text
    return ""


def parse_expires(text: str) -> date:
    try:
        exp = static_tokens.parse_expires(text)
    except ValueError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    if exp <= datetime.now(timezone.utc).date():
        raise SystemExit(f"ERROR: --expires {exp} is not in the future (UTC)")
    return exp


def write_token_file(path: Path, token: str) -> None:
    """Create the file with 0600 and refuse to overwrite an existing one."""
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(f"ERROR: {path} exists; remove it first or pick another --out") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    os.chmod(path, 0o600)


def store_in_keychain(service: str, account: str, token: str) -> None:
    """macOS Keychain via `security`; -U updates an existing item in place."""
    cmd = ["security", "add-generic-password", "-a", account, "-s", service,
           "-w", token, "-U"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except FileNotFoundError:
        raise SystemExit("ERROR: `security` not found; --keychain works on macOS only") from None
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"ERROR: security exited {exc.returncode}: "
                         f"{exc.stderr.decode(errors='replace').strip()}") from exc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--login", required=True, help="machine account name, e.g. agent")
    ap.add_argument("--expires", required=True,
                    help="first day the token is INVALID, YYYY-MM-DD (UTC)")
    pol = ap.add_mutually_exclusive_group()
    pol.add_argument("--deny", help="comma-separated mutating tools to refuse, "
                                   "e.g. delete_note,delete_section")
    pol.add_argument("--readonly", action="store_true", help="refuse every mutating tool")
    dest = ap.add_mutually_exclusive_group()
    dest.add_argument("--out", type=Path, help="write the token to this file (0600, new)")
    dest.add_argument("--keychain", metavar="SERVICE",
                      help="store the token in the macOS Keychain under this service name")
    ap.add_argument("--account", help="Keychain account name (default: --login)")
    ap.add_argument("--hash-only", action="store_true",
                    help="do not generate; hash an existing token read with --from-file")
    ap.add_argument("--from-file", type=Path, help="file holding an existing token")
    ap.add_argument("--token", help=argparse.SUPPRESS)  # trap, see below
    args = ap.parse_args(argv)

    if args.token is not None:
        raise SystemExit("ERROR: never pass the token as an argument (it lands in shell "
                         "history and transcripts); use --hash-only --from-file <path>")
    if not static_tokens.LOGIN_RE.match(args.login):
        raise SystemExit("ERROR: --login must be [A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

    expires = parse_expires(args.expires)
    policy = build_policy(args.deny, args.readonly)

    if args.hash_only:
        if not args.from_file:
            raise SystemExit("ERROR: --hash-only needs --from-file <path>")
        if args.out or args.keychain:
            raise SystemExit("ERROR: --hash-only does not write the token anywhere")
        token = args.from_file.read_text(encoding="utf-8").strip()
        if not static_tokens.TOKEN_RE.match(token):
            raise SystemExit("ERROR: the file does not hold a token of the expected form")
    else:
        if not (args.out or args.keychain):
            raise SystemExit("ERROR: choose where the token goes: --out <file> or "
                             "--keychain <service>")
        token = static_tokens.generate_token()
        if args.out:
            write_token_file(args.out, token)
        else:
            store_in_keychain(args.keychain, args.account or args.login, token)

    print(static_tokens.format_line(args.login.lower(), static_tokens.hash_token(token),
                                    expires, policy))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
