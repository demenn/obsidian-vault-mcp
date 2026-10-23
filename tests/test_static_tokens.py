#!/usr/bin/env python3
"""Offline tests for static machine-account tokens of the MCP server.

Usage: python tests/test_static_tokens.py

Covers static_tokens.py (hash file parsing, mtime re-read, expiry, policy)
and the issue tool's pure functions, plus the guard that every
``@mcp.tool`` in server.py is either a known read tool or a ``_journaled``
mutating tool (a writer added outside ``Vault`` would bypass the policy).
server.py is read as text through ``ast`` — never imported, CI has no fastmcp.

Contract: docs/static-tokens.md.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from vault_mcp import static_tokens as st  # noqa: E402
from vault_mcp import vaultops  # noqa: E402

sys.path.insert(0, str(REPO / "tools"))
import issue_token  # noqa: E402

failures: list[str] = []


def check(cond: bool, label: str):
    print(("ok   " if cond else "FAIL ") + label)
    if not cond:
        failures.append(label)


def raises(fn, exc_type, label):
    try:
        fn()
    except exc_type as exc:
        check(True, label)
        return exc
    except Exception as exc:  # noqa: BLE001
        check(False, f"{label} (получили {type(exc).__name__}: {exc})")
        return None
    check(False, f"{label} (исключения не было)")
    return None


KNOWN = frozenset(vaultops.MUTATING_TOOLS)
FAR = date(2099, 1, 1)


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "conf"
        self.dir.mkdir()
        self.path = self.dir / "static-tokens"
        self.logs = Path(self.tmp.name) / "logs"
        self.store = st.StaticTokenStore(self.path, known_tools=KNOWN)
        self._tick = 0

    def write(self, *lines: str):
        """Write the file and force a DIFFERENT mtime (same-second rewrites)."""
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._tick += 1
        t = 1_700_000_000 + self._tick * 10
        os.utime(self.path, (t, t))

    def line(self, login: str, token: str, expires=FAR, policy: str = "") -> str:
        return st.format_line(login, st.hash_token(token), expires, policy)

    def journal(self) -> list[dict]:
        f = self.logs / st.AUTH_JOURNAL
        if not f.is_file():
            return []
        return [json.loads(ln) for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def close(self):
        self.tmp.cleanup()


def test_accept_unknown_expired():
    f = Fixture()
    try:
        t1, t2 = st.generate_token(), st.generate_token()
        f.write("# login algo hash expires policy", "", f.line("agent", t1))
        e = f.store.lookup(t1)
        check(e.login == "agent" and e.denied == frozenset(), "токен принят, комментарии и пустые строки пропущены")
        check(f.store.enabled, "файл с одной корректной строкой включает статический вход")
        raises(lambda: f.store.lookup(t2), st.UnknownToken, "неизвестный токен отклонён")
        near_miss = t1[:-1] + ("A" if t1[-1] != "A" else "B")
        raises(lambda: f.store.lookup(near_miss), st.UnknownToken, "токен с одним другим символом отклонён")

        f.write(f.line("agent", t1, expires=date(2026, 9, 1)))
        exc = raises(lambda: f.store.lookup(t1, now=datetime(2026, 9, 2, tzinfo=timezone.utc)),
                     st.ExpiredToken, "просроченный токен отклонён")
        check(exc is not None and exc.login == "agent" and exc.expires == date(2026, 9, 1),
              "у просрочки есть логин и дата")
        f.write(f.line("agent", t1, expires=date(2026, 9, 3)))
        ok = f.store.lookup(t1, now=datetime(2026, 9, 2, 23, 59, tzinfo=timezone.utc))
        check(ok.login == "agent", "последний день действия: 23:59 UTC накануне даты принят")
        raises(lambda: f.store.lookup(t1, now=datetime(2026, 9, 3, 0, 0, tzinfo=timezone.utc)),
               st.ExpiredToken, "полночь UTC даты истечения: уже отклонён")
        check(ok.expires_at() == int(datetime(2026, 9, 3, tzinfo=timezone.utc).timestamp()),
              "expires_at это полночь UTC даты истечения в секундах Unix")
    finally:
        f.close()


def test_reread_without_restart():
    f = Fixture()
    try:
        t1, t2 = st.generate_token(), st.generate_token()
        f.write(f.line("agent", t1))
        f.store.lookup(t1)
        f.store.lookup(t1)
        check(f.store.reloads == 1, "неизменённый файл разобран один раз на два запроса")

        f.write(f.line("agent", t2))
        check(f.store.lookup(t2).login == "agent", "замена хеша: новый токен принят без пересоздания store")
        raises(lambda: f.store.lookup(t1), st.UnknownToken, "замена хеша: старый токен отклонён")
        check(f.store.reloads == 2, "изменённый файл разобран заново ровно один раз")

        f.write("# revoked")
        raises(lambda: f.store.lookup(t2), st.UnknownToken, "отзыв удалением строки")
        check(not f.store.enabled, "файл без строк выключает статический вход")

        f.path.unlink()
        raises(lambda: f.store.lookup(t2), st.UnknownToken, "файл удалён: ничего не принимается")
        check(not f.store.enabled, "нет файла: статический вход выключен")

        f.write(f.line("agent", t2))
        check(f.store.lookup(t2).login == "agent", "файл появился позже: принят без перезапуска")

        empty = st.StaticTokenStore(None, known_tools=KNOWN)
        check(not empty.enabled, "MCP_STATIC_TOKENS_FILE не задан: выключено")
        raises(lambda: empty.lookup(t2), st.UnknownToken, "MCP_STATIC_TOKENS_FILE не задан: отклонено")
    finally:
        f.close()


def test_bad_lines_and_policy():
    f = Fixture()
    try:
        t1, t2, t3 = st.generate_token(), st.generate_token(), st.generate_token()
        bad_hash = "agent sha256 zzzz 2027-03-01"
        f.write(bad_hash, f.line("agent2", t2), "agent3 md5 " + "0" * 64 + " 2027-03-01",
                "x y", f.line("agent", t1, policy="deny=delete_nte"))
        check(f.store.lookup(t2).login == "agent2", "битые строки не мешают корректной")
        check(len(f.store.errors) == 4, f"четыре битые строки учтены ({len(f.store.errors)})")
        check(all("line " in e for e in f.store.errors), "в ошибках есть номер строки")
        check(not any("zzzz" in e or "0000" in e for e in f.store.errors), "в ошибках нет содержимого хеша")
        raises(lambda: f.store.lookup(t1), st.UnknownToken, "политика с опечаткой отбрасывает строку целиком")

        f.write(f.line("agent", t1, policy="deny=delete_note,delete_section"),
                f.line("ro", t3, policy="readonly"))
        e = f.store.lookup(t1)
        check(e.denied == frozenset({"delete_note", "delete_section"}) and not e.readonly,
              "deny= разобран в множество инструментов")
        check(e.policy == "deny=delete_note,delete_section", "политика рендерится обратно той же строкой")
        r = f.store.lookup(t3)
        check(r.readonly and r.denied == frozenset({st.READONLY_ALL}), "readonly → сентинел «все мутирующие»")

        raises(lambda: st.parse_policy("allow=x", KNOWN), ValueError, "неизвестный вид политики это ошибка")
        raises(lambda: st.parse_policy("deny=", KNOWN), ValueError, "пустой deny= это ошибка")
        check(st.parse_policy("", KNOWN) == frozenset(), "пустая политика → пустое множество")
    finally:
        f.close()


def test_rejection_journal():
    f = Fixture()
    try:
        t = st.generate_token()
        st.journal_rejection(f.logs, reason="unknown", token=t)
        st.journal_rejection(f.logs, reason="expired", token=t, login="agent")
        j = f.journal()
        check(len(j) == 2 and j[0]["outcome"] == "rejected" and j[0]["reason"] == "unknown"
              and "login" not in j[0], "запись unknown без логина")
        check(j[1]["reason"] == "expired" and j[1]["login"] == "agent", "запись expired с логином")
        check(all(r["fp"] == st.fingerprint(t) and len(r["fp"]) == 12 for r in j), "отпечаток: 12 hex")
        check(not any(t in json.dumps(r) for r in j), "сам токен в журнал не попадает")
        blocked = Path(f.tmp.name) / "file-not-dir"
        blocked.write_text("x")
        st.journal_rejection(blocked / "sub", reason="unknown", token=t)
        check(True, "недоступный каталог журнала не роняет вызов")
        st.journal_rejection(None, reason="unknown", token=t)
        check(True, "пустой log_dir: молча ничего")
        check(st.looks_like_ours("ovm_abc") and not st.looks_like_ours("eyJhbGciOi"),
              "префикс отличает наш токен от JWT")
    finally:
        f.close()


def test_token_format_and_issue_tool():
    t = st.generate_token()
    check(bool(st.TOKEN_RE.match(t)), "сгенерированный токен: ovm_ + 43 символа base64url")
    check(len({st.generate_token() for _ in range(50)}) == 50, "токены не повторяются")
    line = st.format_line("agent", st.hash_token(t), date(2027, 3, 1), "readonly")
    e = st.parse_line(line, 1, KNOWN)
    check(e is not None and e.login == "agent" and e.expires == date(2027, 3, 1) and e.readonly,
          "format_line ↔ parse_line обратимы")
    check(st.parse_line("   # only a comment", 1, KNOWN) is None, "комментарий → None")
    check(st.parse_line("agent sha256 " + "a" * 64 + " 2027-01-01  # trailing", 1, KNOWN).login == "agent",
          "хвостовой комментарий отрезается")

    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "tok"
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = issue_token.main(["--login", "Agent", "--expires", FAR.isoformat(),
                                       "--deny", "delete_note,delete_section", "--out", str(out)])
        printed = buf.getvalue().strip().splitlines()
        check(rc == 0 and len(printed) == 1, "инструмент печатает ровно одну строку")
        fields = printed[0].split()
        check(fields[0] == "agent" and fields[1] == "sha256" and fields[3] == FAR.isoformat()
              and fields[4] == "deny=delete_note,delete_section", "строка для файла хешей в нужной форме")
        token = out.read_text(encoding="utf-8").strip()
        check(bool(st.TOKEN_RE.match(token)), "токен записан в файл")
        check(st.hash_token(token) == fields[2], "sha256 содержимого файла равен хешу в строке")
        check(oct(out.stat().st_mode & 0o777) == "0o600", "файл токена 0600")
        check(token not in buf.getvalue(), "токен не напечатан")

        buf2 = io.StringIO()
        with redirect_stdout(buf2):
            rc2 = issue_token.main(["--login", "agent", "--expires", FAR.isoformat(),
                                        "--readonly", "--hash-only", "--from-file", str(out)])
        check(rc2 == 0 and buf2.getvalue().split()[2] == fields[2]
              and buf2.getvalue().split()[4] == "readonly", "--hash-only даёт тот же хеш с новой политикой")

        raises(lambda: issue_token.main(["--login", "agent", "--expires", FAR.isoformat(),
                                             "--out", str(out)]), SystemExit,
               "существующий --out не перезаписывается")
        raises(lambda: issue_token.main(["--login", "agent", "--expires", FAR.isoformat(),
                                             "--token", "ovm_x", "--out", str(Path(d) / "t2")]),
               SystemExit, "--token отвергается")
        raises(lambda: issue_token.main(["--login", "agent", "--expires", FAR.isoformat(),
                                             "--deny", "delete_nte", "--out", str(Path(d) / "t3")]),
               SystemExit, "неизвестный инструмент в --deny отвергается")
        raises(lambda: issue_token.main(["--login", "agent", "--expires", "2020-01-01",
                                             "--out", str(Path(d) / "t4")]),
               SystemExit, "дата в прошлом отвергается")
        raises(lambda: issue_token.main(["--login", "agent", "--expires", FAR.isoformat()]),
               SystemExit, "без --out/--keychain отказ")
        check(not (Path(d) / "t2").exists() and not (Path(d) / "t3").exists(), "при отказе файл не создан")


READ_TOOLS = {
    "list_notes", "search_notes", "read_note", "note_info", "search_by_tag",
    "get_backlinks", "youtube_transcript",
}
EXPECTED_MUTATING = {
    "create_note", "write_note", "append_to_note", "patch_note", "edit_frontmatter",
    "delete_section", "delete_note", "rename_note",
}


def server_tool_names() -> list[str]:
    tree = ast.parse((REPO / "vault_mcp" / "server.py").read_text(encoding="utf-8"))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                target = d.func if isinstance(d, ast.Call) else d
                if isinstance(target, ast.Attribute) and target.attr == "tool" \
                        and isinstance(target.value, ast.Name) and target.value.id == "mcp":
                    names.append(node.name)
    return names


def test_every_server_tool_is_classified():
    names = server_tool_names()
    check(len(names) == 15, f"server.py объявляет 15 инструментов ({len(names)})")
    check(KNOWN == EXPECTED_MUTATING, f"MUTATING_TOOLS собран из _journaled: {sorted(KNOWN)}")
    stray = [n for n in names if n not in READ_TOOLS and n not in KNOWN]
    check(not stray, f"каждый @mcp.tool либо читающий, либо под политикой: лишние {stray}")
    missing = sorted(KNOWN - set(names))
    check(not missing, f"каждый мутирующий метод Vault выставлен как инструмент: нет {missing}")
    tree = ast.parse((REPO / "vault_mcp" / "static_tokens.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    check(not (imported & {"fastmcp", "mcp", "vaultops", "server"}),
          f"static_tokens.py не импортирует ни fastmcp, ни vaultops ({sorted(imported)})")


def test_authorize():
    """The allow-list decision of AllowListMiddleware, incl. fail-closed on empty."""
    claims = ("login", "email")
    allowed = {"alice", "her@gmail.com"}
    check(st.authorize({"login": "Alice"}, allowed, claims) == ("alice", "", frozenset()),
          "логин из списка допущен без учёта регистра")
    check(st.authorize({"email": "her@gmail.com"}, allowed, claims)[0] == "her@gmail.com",
          "второй claim (email) берётся, когда первого нет")
    exc = raises(lambda: st.authorize({"login": "stranger"}, allowed, claims),
                 st.AccessDenied, "логин не из списка отклонён")
    check("stranger" in str(exc), "в отказе назван логин")
    raises(lambda: st.authorize({}, allowed, claims), st.AccessDenied,
           "токен без claim личности отклонён")
    # Fail closed: an empty allow-list used to switch the check off.
    exc = raises(lambda: st.authorize({"login": "alice"}, set(), claims),
                 st.AccessDenied, "пустой allow-list отклоняет даже знакомый логин")
    check("MCP_ALLOWED_USERS" in str(exc), "отказ называет пустую переменную")
    raises(lambda: st.authorize({"login": "stranger"}, frozenset(), claims),
           st.AccessDenied, "пустой allow-list отклоняет чужого")
    # Static identities carry their own allow-list (the hash file line).
    check(st.authorize({"login": "agent", "auth": "static", "deny": ["delete_note"]},
                       set(), claims) == ("agent", "static", frozenset({"delete_note"})),
          "статическая учётка проходит при пустом allow-list, политика передана")
    check(st.authorize({"login": "agent", "auth": "static"}, allowed, claims)[1] == "static",
          "статическая учётка не в allow-list всё равно проходит")
    raises(lambda: st.authorize({"auth": "static"}, allowed, claims), st.AccessDenied,
           "статический токен без логина отклонён")


def main() -> int:
    for fn in (
        test_accept_unknown_expired,
        test_reread_without_restart,
        test_bad_lines_and_policy,
        test_rejection_journal,
        test_token_format_and_issue_tool,
        test_every_server_tool_is_classified,
        test_authorize,
    ):
        print(f"\n── {fn.__name__}")
        fn()
    print()
    if failures:
        print(f"{len(failures)} проверок упало:")
        for f in failures:
            print("  - " + f)
        return 1
    print("все проверки прошли")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
