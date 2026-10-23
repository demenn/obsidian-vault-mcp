#!/usr/bin/env python3
"""Acceptance probe for a static machine-account token against the live MCP.

Stdlib only (no fastmcp needed). The token comes from the environment and is
never printed; run it yourself so the value never enters an agent transcript:

    VAULT_MCP_TOKEN=$(cat /path/to/token-file) \
        VAULT_MCP_URL=https://vault-mcp.example.com/mcp \
        python tools/probe_static_token.py

What it does (docs/static-tokens.md, acceptance scenarios):
  1. initialize + tools/list         → the token is accepted, session opened
  2. create_note in _probes          → a write is attributed to the account
  3. patch_note on it                → editing is allowed under deny=delete_*
  4. delete_note on it               → refused by the account policy
  5. read_note                       → reads keep working
Exit code 0 when every step matches; the note stays for the human to delete
(that is the point of the policy).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("VAULT_MCP_URL", "http://localhost:8000/mcp").rstrip("/")
TOKEN = os.environ.get("VAULT_MCP_TOKEN", "").strip()
PROTO = "2025-06-18"
NOTE_TITLE = "mcp-static-token-acceptance"
NOTE_FOLDER = "_probes"

failures: list[str] = []


def check(cond: bool, label: str):
    print(("ok   " if cond else "FAIL ") + label)
    if not cond:
        failures.append(label)


class Client:
    def __init__(self):
        self.session = ""
        self._id = 0

    def _post(self, payload: dict) -> tuple[int, dict, dict | None]:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(URL, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("Authorization", f"Bearer {TOKEN}")
        req.add_header("MCP-Protocol-Version", PROTO)
        if self.session:
            req.add_header("Mcp-Session-Id", self.session)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                status = resp.status
                headers = {k.lower(): v for k, v in resp.headers.items()}
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in exc.headers.items()}
            return exc.code, headers, None
        sid = headers.get("mcp-session-id")
        if sid:
            self.session = sid
        msg = None
        if raw.strip():
            if headers.get("content-type", "").startswith("text/event-stream"):
                for line in raw.splitlines():
                    if line.startswith("data:"):
                        try:
                            candidate = json.loads(line[5:].strip())
                        except json.JSONDecodeError:
                            continue
                        if candidate.get("id") == payload.get("id"):
                            msg = candidate
            else:
                msg = json.loads(raw)
        return status, headers, msg

    def request(self, method: str, params: dict | None = None):
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            payload["params"] = params
        return self._post(payload)

    def notify(self, method: str):
        return self._post({"jsonrpc": "2.0", "method": method})

    def call_tool(self, name: str, **arguments) -> tuple[int, str]:
        status, _h, msg = self.request("tools/call", {"name": name, "arguments": arguments})
        if msg is None:
            return status, ""
        if "error" in msg:
            return status, "JSONRPC-ERROR: " + json.dumps(msg["error"], ensure_ascii=False)
        content = (msg.get("result") or {}).get("content") or []
        text = "\n".join(c.get("text", "") for c in content if c.get("type") == "text")
        return status, text


def main() -> int:
    if not TOKEN:
        print("VAULT_MCP_TOKEN is not set", file=sys.stderr)
        return 2
    c = Client()
    status, headers, msg = c.request("initialize", {
        "protocolVersion": PROTO, "capabilities": {},
        "clientInfo": {"name": "mcp-static-token-probe", "version": "1"},
    })
    if status != 200:
        print(f"FAIL initialize: HTTP {status} {headers.get('www-authenticate', '')[:120]}")
        return 1
    check(msg is not None and "result" in msg and bool(c.session),
          f"1. токен принят: initialize 200, сессия открыта, сервер "
          f"{(msg or {}).get('result', {}).get('serverInfo', {}).get('name', '?')}")
    c.notify("notifications/initialized")
    status, _h, msg = c.request("tools/list")
    tools = [t["name"] for t in ((msg or {}).get("result") or {}).get("tools", [])]
    check(status == 200 and "create_note" in tools and "delete_note" in tools,
          f"1. tools/list: {len(tools)} инструментов")

    path = f"{NOTE_FOLDER}/{NOTE_TITLE}.md"
    status, text = c.call_tool("note_info", path=path)
    if text.startswith("ok") or "sha256" in text or "hash" in text:
        print(f"     заметка {path} уже есть от прошлого прогона, create_note пропущен")
    else:
        status, text = c.call_tool("create_note", title=NOTE_TITLE, folder=NOTE_FOLDER,
                                   content="Проверка статического токена. Удалить руками.\n")
        check(status == 200 and text.startswith("ok:"),
              f"2. create_note агентом проходит: {text.splitlines()[0] if text else status}")

    status, text = c.call_tool("patch_note", path=path, heading="Ход", content="- строка от агента",
                               operation="append", create_if_missing=True)
    check(status == 200 and text.startswith("ok:"),
          f"3. patch_note (правка) разрешён: {text.splitlines()[0] if text else status}")

    status, text = c.call_tool("delete_note", path=path)
    check(status == 200 and text.strip() == "ERROR: tool 'delete_note' is denied for user 'agent'",
          f"4. delete_note отклонён политикой: {text.strip()[:90]}")

    status, text = c.call_tool("delete_section", path=path, heading="Ход")
    check(status == 200 and "is denied for user 'agent'" in text,
          f"4. delete_section отклонён политикой: {text.strip()[:90]}")

    status, text = c.call_tool("read_note", path=path)
    check(status == 200 and "строка от агента" in text, "5. read_note работает, правка на месте")

    print()
    if failures:
        print(f"{len(failures)} проверок упало")
        return 1
    print("все проверки прошли; заметку _probes/mcp-static-token-acceptance.md "
          "удаляет человек")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
