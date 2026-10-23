#!/usr/bin/env python3
"""Offline tests for the MCP server's vault operations.

Usage: python tests/test_vaultops.py

Checks the write contract from docs/write-contract.md against a throwaway
vault in a temp dir: no network, no fastmcp, no live vault. The module under
test is vaultops.py, which is deliberately free of any fastmcp import
precisely so this file can exist.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from vault_mcp import vaultops  # noqa: E402
from vault_mcp.vaultops import Conflict, NotFound, Vault, VaultError  # noqa: E402

failures: list[str] = []


def check(cond: bool, label: str):
    print(("ok   " if cond else "FAIL ") + label)
    if not cond:
        failures.append(label)


def raises(fn, exc_type, label):
    try:
        fn()
    except exc_type:
        check(True, label)
        return
    except Exception as exc:  # noqa: BLE001
        check(False, f"{label} (получили {type(exc).__name__}: {exc})")
        return
    check(False, f"{label} (исключения не было)")


class Fixture:
    """A throwaway vault plus a logs dir outside it."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root / "vault"
        self.logs = root / "logs"
        (self.root / "10_Notes").mkdir(parents=True)
        (self.root / "00_Inbox/daily").mkdir(parents=True)
        self.v = Vault(self.root, inbox_rel="00_Inbox/daily", tz=timezone.utc,
                       log_dir=self.logs)

    def write(self, rel: str, text: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def journal(self) -> list[dict]:
        f = self.logs / "mcp-writes.jsonl"
        if not f.is_file():
            return []
        return [json.loads(ln) for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def stray_temp_files(self) -> list[str]:
        return [p.name for p in self.root.rglob(".*.tmp")]

    def close(self):
        self.tmp.cleanup()


NOTE = """---
title: Заметка
status: next
tags:
  - project/demo
---

# Заметка

Преамбула про суть.

## Раздел A

Тело A.

## Раздел B

Тело B.
"""


# 1 ─────────────────────────────────────────────────────────────────────────
def test_create_note_refuses_existing():
    f = Fixture()
    try:
        f.v.create_note("Моя задача", "тело", folder="10_Notes")
        raises(lambda: f.v.create_note("Моя задача", "другое тело", folder="10_Notes"),
               VaultError, "create_note на существующем пути падает с ошибкой")
        files = sorted(p.name for p in (f.root / "10_Notes").glob("*.md"))
        check(files == ["Моя задача.md"], f"дубликат не создан: {files}")
        check(f.read("10_Notes/Моя задача.md").count("тело") == 1,
              "содержимое первой заметки не тронуто")
        r1 = f.v.create_note("Дроп", "раз")
        check(r1.startswith("ok: create_note 00_Inbox/daily/"),
              "инбоксная заметка создаётся по-прежнему")
    finally:
        f.close()


# 2 ─────────────────────────────────────────────────────────────────────────
def test_atomic_and_no_op_write():
    f = Fixture()
    try:
        p = f.write("10_Notes/A.md", NOTE)
        before = p.stat().st_mtime_ns
        out = f.v.write_note("10_Notes/A.md", NOTE)
        check("(без изменений)" in out, "повторная запись тем же содержимым: без изменений")
        check(p.stat().st_mtime_ns == before, "mtime не тронут при холостой записи")
        f.v.write_note("10_Notes/A.md", NOTE + "\nхвост\n")
        check(p.stat().st_mtime_ns != before, "реальная запись меняет файл")
        check(f.stray_temp_files() == [], "временных файлов не осталось")
    finally:
        f.close()


# 3 ─────────────────────────────────────────────────────────────────────────
def test_expected_hash():
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        h = vaultops.hash_text(NOTE)
        raises(lambda: f.v.write_note("10_Notes/A.md", "новое\n",
                                      expected_hash="deadbeefdeadbeef"),
               Conflict, "неверный expected_hash отклоняет запись")
        check(f.read("10_Notes/A.md") == NOTE, "файл при конфликте не изменён")
        raises(lambda: f.v.write_note("10_Notes/A.md", "новое\n", expected_hash="abc"),
               VaultError, "слишком короткий expected_hash отклонён")
        f.v.write_note("10_Notes/A.md", "новое\n", expected_hash=h[:8])
        check(f.read("10_Notes/A.md") == "новое\n", "префикс в 8 символов принимается")
        f.v.write_note("10_Notes/A.md", "ещё новее\n",
                       expected_hash=vaultops.hash_text("новое\n"))
        check(f.read("10_Notes/A.md") == "ещё новее\n", "полный хеш принимается")

        refusals = [r for r in f.journal() if r.get("ok") is False]
        check(any(r["tool"] == "write_note" and "conflict" in r.get("error", "")
                  for r in refusals),
              "отказ по конфликту записан в журнал")
    finally:
        f.close()


# 4 ─────────────────────────────────────────────────────────────────────────
def test_delete_note():
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        out = f.v.delete_note("10_Notes/A.md")
        check(not (f.root / "10_Notes/A.md").exists(), "заметка исчезла с исходного пути")
        trashed = sorted((f.root / ".trash").glob("*.md"))
        check(len(trashed) == 1 and trashed[0].read_text(encoding="utf-8") == NOTE,
              "заметка целиком лежит в .trash и читается")
        check(".trash/" in out, f"ответ называет путь в корзине: {out}")
        check(f.v.list_notes() == "(no notes)", "корзина не видна в листинге")

        f.write("10_Notes/B.md", NOTE)
        f.v.delete_note("10_Notes/B.md", permanent=True)
        check(not (f.root / "10_Notes/B.md").exists() and
              len(list((f.root / ".trash").glob("*.md"))) == 1,
              "permanent=True удаляет мимо корзины")

        rec = [r for r in f.journal() if r["tool"] == "delete_note"]
        check(len(rec) == 2 and rec[0].get("trash_path", "").startswith(".trash/"),
              "оба удаления записаны в журнал")
        raises(lambda: f.v.delete_note("10_Notes/нет.md"), NotFound,
               "удаление несуществующей заметки: not found")
    finally:
        f.close()


# 5 ─────────────────────────────────────────────────────────────────────────
def test_delete_section():
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        f.v.delete_section("10_Notes/A.md", "Раздел A")
        text = f.read("10_Notes/A.md")
        check("Раздел A" not in text and "Тело A." not in text,
              "заголовок удалён вместе с телом")
        check("## Раздел B" in text and "Тело B." in text, "соседняя секция цела")
        check("Преамбула про суть." in text, "преамбула цела")
        check("\n\n\n" not in text, "лишние пустые строки схлопнуты")

        nested = ("# T\n\n## Проект\n\n### Задачи\n\nпункт\n\n### Риски\n\nриск\n\n"
                  "## Другое\n\nхвост\n")
        f.write("10_Notes/N.md", nested)
        f.v.delete_section("10_Notes/N.md", "Проект::Задачи")
        t2 = f.read("10_Notes/N.md")
        check("### Задачи" not in t2 and "пункт" not in t2, "вложенный якорь A::B работает")
        check("### Риски" in t2 and "## Другое" in t2, "соседи вложенной секции целы")

        raises(lambda: f.v.delete_section("10_Notes/A.md", "Нет такой"), NotFound,
               "несуществующий заголовок: not found")
        raises(lambda: f.v.delete_section("10_Notes/A.md", ""), VaultError,
               "пустой heading в delete_section отклонён")
    finally:
        f.close()


# 6 ─────────────────────────────────────────────────────────────────────────
def test_preamble_patch():
    """Пустой heading = область между frontmatter и ПЕРВЫМ заголовком.

    В типовой заметке первый заголовок это H1, поэтому преамбула обычно пуста, и
    единственный осмысленный случай там — prepend выше H1 (ровно то, чего не
    хватало). Заметка с вводным абзацем до первого заголовка проверяет остальные
    две операции.
    """
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        f.v.patch_note("10_Notes/A.md", "", "> [!tip] Сверху", operation="prepend")
        text = f.read("10_Notes/A.md")
        head = text.split("---\n", 2)[2]
        check(head.lstrip("\n").startswith("> [!tip] Сверху"),
              "prepend с пустым heading встал сразу после frontmatter")
        check(text.index("> [!tip] Сверху") < text.index("# Заметка"),
              "блок стоит ВЫШЕ H1")
        check("## Раздел A" in text and "Тело B." in text, "секции не задеты")

        intro = ("---\ntitle: T\n---\n\nВводный абзац.\n\n# T\n\n"
                 "## Раздел\n\nтело\n")
        f.write("10_Notes/B.md", intro)
        f.v.patch_note("10_Notes/B.md", "", "хвост преамбулы", operation="append")
        t2 = f.read("10_Notes/B.md")
        check(t2.index("Вводный абзац.") < t2.index("хвост преамбулы") < t2.index("# T"),
              "append с пустым heading встал в конец преамбулы, до первого заголовка")

        f.write("10_Notes/C.md", intro)
        f.v.patch_note("10_Notes/C.md", "", "только это", operation="replace")
        t3 = f.read("10_Notes/C.md")
        check("Вводный абзац." not in t3 and "только это" in t3
              and "## Раздел" in t3 and "# T" in t3,
              "replace заменил преамбулу и не задел ни H1, ни секции")

        # A note with no headings at all: the preamble is the whole body.
        f.write("10_Notes/D.md", "---\ntitle: D\n---\n\nодна строка\n")
        f.v.patch_note("10_Notes/D.md", "", "вторая строка", operation="append")
        t4 = f.read("10_Notes/D.md")
        check(t4.index("одна строка") < t4.index("вторая строка"),
              "в заметке без заголовков преамбула это всё тело")
    finally:
        f.close()


# 7 ─────────────────────────────────────────────────────────────────────────
def test_dry_run():
    f = Fixture()
    try:
        p = f.write("10_Notes/A.md", NOTE)
        before = p.read_bytes()
        for label, call in (
            ("write_note", lambda: f.v.write_note("10_Notes/A.md", "иначе\n", dry_run=True)),
            ("patch_note", lambda: f.v.patch_note("10_Notes/A.md", "Раздел A", "ещё", dry_run=True)),
            ("delete_section", lambda: f.v.delete_section("10_Notes/A.md", "Раздел A", dry_run=True)),
            ("delete_note", lambda: f.v.delete_note("10_Notes/A.md", dry_run=True)),
            ("edit_frontmatter", lambda: f.v.edit_frontmatter("status", "10_Notes/A.md", "done", dry_run=True)),
        ):
            out = call()
            check(out.startswith("dry-run:"), f"{label}: ответ помечен dry-run")
            check(p.read_bytes() == before, f"{label}: файл не тронут")
        out = f.v.write_note("10_Notes/A.md", "иначе\n", dry_run=True)
        check("+иначе" in out and "---" in out, "dry_run возвращает unified diff")
        check(all(r.get("dry_run") for r in f.journal()),
              "все холостые вызовы записаны в журнал с пометкой dry_run")
    finally:
        f.close()


# Каноническое целое — спека docs/spec/2026-10-05-edit-frontmatter-unquoted.md
def test_edit_frontmatter_canonical_int():
    f = Fixture()
    try:
        f.write("10_Notes/A.md",
                "---\ntitle: A\nstatus: next\ncreated: '2026-10-05'\n"
                "tags:\n- project/demo\n---\n\n# A\n\nТело.\n")

        f.v.edit_frontmatter("tier", "10_Notes/A.md", "2")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(isinstance(data["tier"], int) and data["tier"] == 2,
              "set: каноническое целое хранится числом")
        check("\ntier: 2\n" in f.read("10_Notes/A.md"),
              "в файле голое число без кавычек")

        f.v.edit_frontmatter("depth", "10_Notes/A.md", "-2")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(isinstance(data["depth"], int) and data["depth"] == -2,
              "отрицательное каноническое целое тоже число")

        for field, raw in (("a", "007"), ("b", "+2"), ("c", " 2 "), ("d", "true")):
            f.v.edit_frontmatter(field, "10_Notes/A.md", raw)
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(data["a"] == "007" and data["b"] == "+2"
              and data["c"] == " 2 " and data["d"] == "true",
              "неканонические строки остаются строками")
        t = f.read("10_Notes/A.md")
        check("'007'" in t and "'+2'" in t and "' 2 '" in t and "'true'" in t,
              "неканонические строки записаны в кавычках, как сегодня")

        f.v.edit_frontmatter("created", "10_Notes/A.md", "2026-10-06")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(data["created"] == "2026-10-06",
              "дата-подобная строка остаётся строкой")
        check(data["status"] == "next",
              "существующие строковые поля не меняют форму")

        f.v.edit_frontmatter("tags", "10_Notes/A.md", "2", operation="append")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(data["tags"] == ["project/demo", 2],
              "append: целое дописывается в список числом")

        f.v.edit_frontmatter("year", "10_Notes/A.md", "7", operation="append")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(data["year"] == [7],
              "append в отсутствующее поле создаёт список из числа")

        before = (f.root / "10_Notes/A.md").read_bytes()
        out = f.v.edit_frontmatter("tier", "10_Notes/A.md", "3", dry_run=True)
        check(out.startswith("dry-run:"), "dry_run помечен")
        check("+tier: 3" in out, "dry_run показывает голое число в диффе")
        check((f.root / "10_Notes/A.md").read_bytes() == before,
              "dry_run файл не трогает")

        f.v.edit_frontmatter("marker", "10_Notes/A.md", "x")
        t = f.read("10_Notes/A.md")
        check("marker: x" in t and t.count("---") >= 2,
              "после типизированных записей блок frontmatter цел")
    finally:
        f.close()


# 8 ─────────────────────────────────────────────────────────────────────────
LINKER = """---
title: Ссылающаяся
related: Старое имя
source_path: "10_Notes/Старое имя.md"
---

# Ссылающаяся

- [[Старое имя]]
- [[Старое имя|Алиас]]
- [[Старое имя#Раздел A]]
- [[10_Notes/Старое имя]]
- [[Старое имя и что-то ещё]]

| задача | ссылка |
|---|---|
| раз | [[Старое имя\\|в таблице]] |
"""


def test_rename_note():
    f = Fixture()
    try:
        f.write("10_Notes/Старое имя.md",
                "---\ntitle: Старое имя\nstatus: next\n---\n\n# Старое имя\n\nтело\n")
        f.write("10_Notes/Ссылающаяся.md", LINKER)
        f.write("10_Notes/tasks/_boards/Space/List.md",
                "## next\n\n- [ ] [[Старое имя]]\n")
        out = f.v.rename_note("10_Notes/Старое имя.md", "Новое имя")

        check((f.root / "10_Notes/Новое имя.md").exists()
              and not (f.root / "10_Notes/Старое имя.md").exists(),
              "файл переименован")
        own = f.read("10_Notes/Новое имя.md")
        check("title: Новое имя" in own and "# Новое имя" in own,
              "title и H1 обновлены")

        linker = f.read("10_Notes/Ссылающаяся.md")
        for form in ("[[Новое имя]]", "[[Новое имя|Алиас]]", "[[Новое имя#Раздел A]]",
                     "[[10_Notes/Новое имя]]", "[[Новое имя\\|в таблице]]"):
            check(form in linker, f"переписана форма ссылки {form}")
        check("related: Новое имя" in linker, "скаляр frontmatter переписан")
        check('source_path: "10_Notes/Новое имя.md"' in linker, "путь в кавычках переписан")
        check("[[Старое имя и что-то ещё]]" in linker,
              "ссылка на ДРУГУЮ заметку с тем же префиксом не тронута")
        check("Старое имя]]" not in linker.replace("[[Старое имя и что-то ещё]]", ""),
              "старых ссылок не осталось")

        board = f.read("10_Notes/tasks/_boards/Space/List.md")
        check("[[Новое имя]]" in board, "карточка на доске в _boards переписана")
        check("links_in=2" in out, f"ответ считает переписанные заметки: {out}")

        f.write("10_Notes/Занято.md", "# Занято\n")
        raises(lambda: f.v.rename_note("10_Notes/Новое имя.md", "Занято"),
               VaultError, "коллизия имени отклонена")
    finally:
        f.close()


# 9 ─────────────────────────────────────────────────────────────────────────
def test_listing_fields_and_where():
    f = Fixture()
    try:
        f.write("10_Notes/t1.md", "---\ntitle: Раз\nstatus: next\ncategory: task\n"
                                  "tags:\n  - project/demo\n---\n\n# Раз\n")
        f.write("10_Notes/t2.md", "---\ntitle: Два\nstatus: complete\ncategory: task\n---\n\n# Два\n")
        f.write("10_Notes/t3.md", "---\ntitle: Три\ncategory: idea\n---\n\n# Три\n")

        out = f.v.list_notes("10_Notes", fields="status,category")
        check("10_Notes/t1.md | status=next | category=task" in out,
              "fields печатает поля frontmatter")
        check("10_Notes/t3.md | category=idea" in out,
              "отсутствующее поле просто пропущено")

        out = f.v.list_notes("10_Notes", where="status=next")
        check(out == "10_Notes/t1.md", f"where по равенству: {out}")
        out = f.v.list_notes("10_Notes", where="category=task,status!=complete")
        check(out == "10_Notes/t1.md", f"несколько условий соединяются по И: {out}")
        out = f.v.list_notes("10_Notes", where="status=*")
        check(out.count("\n") == 1, "where key=* оставляет заметки с непустым полем")
        out = f.v.list_notes("10_Notes", where="tags=project/demo")
        check(out == "10_Notes/t1.md", "списочное поле матчится по вхождению")
        raises(lambda: f.v.list_notes("10_Notes", where="мусор"), VaultError,
               "неразобранное условие where отклонено")

        out = f.v.search_notes("Два", fields="status")
        check("status=complete" in out, "search_notes тоже умеет fields")
    finally:
        f.close()


# 10 ────────────────────────────────────────────────────────────────────────
def test_existing_tools_unchanged():
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        f.v.patch_note("10_Notes/A.md", "Раздел A", "дописка")
        t = f.read("10_Notes/A.md")
        check("Тело A.\n\nдописка\n\n## Раздел B" in t, "patch_note append как раньше")

        f.v.patch_note("10_Notes/A.md", "Раздел B", "сверху", operation="prepend")
        t = f.read("10_Notes/A.md")
        check("## Раздел B\nсверху\n" in t, "patch_note prepend как раньше")

        f.v.patch_note("10_Notes/A.md", "Раздел B", "только это", operation="replace")
        t = f.read("10_Notes/A.md")
        check("Тело B." not in t and "только это" in t, "patch_note replace как раньше")

        f.v.patch_note("10_Notes/A.md", "Новая секция", "текст", create_if_missing=True)
        check("## Новая секция\n\nтекст" in f.read("10_Notes/A.md"),
              "create_if_missing создаёт секцию в конце")
        raises(lambda: f.v.patch_note("10_Notes/A.md", "Нет", "x", create_if_missing=False),
               NotFound, "create_if_missing=False падает на отсутствующем заголовке")

        f.v.edit_frontmatter("status", "10_Notes/A.md", "complete")
        f.v.edit_frontmatter("tags", "10_Notes/A.md", "work/personal", operation="append")
        f.v.edit_frontmatter("title", "10_Notes/A.md", operation="delete")
        f.v.edit_frontmatter("priority", "10_Notes/A.md", "2")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/A.md"))
        check(data["status"] == "complete", "edit_frontmatter set")
        check(data["tags"] == ["project/demo", "work/personal"], "edit_frontmatter append")
        check("title" not in data, "edit_frontmatter delete")
        check(isinstance(data["priority"], int) and data["priority"] == 2,
              "edit_frontmatter: целое значение пишется числом (каноническое правило)")

        f.v.append_to_note("10_Notes/A.md", "последняя строка")
        check(f.read("10_Notes/A.md").endswith("последняя строка\n"), "append_to_note")

        check(f.v.get_backlinks("10_Notes/A.md") == "(no backlinks)",
              "get_backlinks на заметке без ссылок")
        f.write("10_Notes/L.md", "# L\n\n[[A]]\n")
        check(f.v.get_backlinks("10_Notes/A.md") == "10_Notes/L.md", "get_backlinks находит ссылку")
        check(f.v.search_by_tag("project") == "10_Notes/A.md",
              "search_by_tag матчит вложенный тег")
        raises(lambda: f.v.read_note("10_Notes/нет.md"), NotFound, "read_note: not found")
        raises(lambda: f.v.resolve("../побег.md"), VaultError, "путь наружу хранилища отклонён")
        raises(lambda: f.v.resolve("10_Notes/файл.txt"), VaultError, "не-.md отклонён")

        info = f.v.note_info("10_Notes/A.md")
        check("sha256: " in info and "headings:" in info and "frontmatter:" in info,
              "note_info отдаёт хеш, frontmatter и оглавление")
        check(vaultops.hash_text(f.read("10_Notes/A.md")) in info,
              "хеш в note_info совпадает с содержимым файла")
    finally:
        f.close()


def test_rename_pins_cache_identity():
    """Переименование не должно осиротить внешние записи о заметке.

    Всё, что ключует данные полем `id:` из frontmatter, переживает смену пути,
    если id проставлен. Значит перед сменой пути `id:` надо выставить, и ровно
    тем значением, под которым запись УЖЕ существует.
    """
    f = Fixture()
    try:
        # Формула одна: naming.note_id, модуль лежит рядом с сервером.
        from vault_mcp.naming import note_id
        rel = "10_Notes/Заметка.md"
        want = note_id(rel)
        check(not hasattr(vaultops, "entity_cache_id"),
              "локальной копии формулы ключа в vaultops нет")
        check("pipeline" not in sys.modules,
              "vaultops не тянет никаких pipeline-модулей")
        check(len(want) == 12 and all(c in "0123456789abcdef" for c in want),
              "ключ это 12 шестнадцатеричных символов")

        f.write("10_Notes/Заметка.md", "---\ntitle: Заметка\n---\n\n# Заметка\n\nтело\n")
        f.v.rename_note("10_Notes/Заметка.md", "Заметка новая")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/Заметка новая.md"))
        check(data.get("id") == note_id("10_Notes/Заметка.md"),
              "проставлен id старого пути, то есть ключ существующей записи кэша")

        # Уже имеющийся id — чужая идентичность, её перезаписывать нельзя.
        f.write("10_Notes/Своя.md", "---\ntitle: Своя\nid: ae1eb35e\n---\n\n# Своя\n")
        f.v.rename_note("10_Notes/Своя.md", "Своя новая")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/Своя новая.md"))
        check(data.get("id") == "ae1eb35e", "существующий id сохранён без изменений")

        # Без frontmatter собственных свойств у заметки нет, и заводить их ради
        # ключа мы не станем — переименование просто проходит как раньше.
        f.write("10_Notes/Голая.md", "# Голая\n\nтело\n")
        f.v.rename_note("10_Notes/Голая.md", "Голая новая")
        check((f.root / "10_Notes/Голая новая.md").exists()
              and "id:" not in f.read("10_Notes/Голая новая.md"),
              "заметке без frontmatter frontmatter не навязывается")
    finally:
        f.close()


# Frontmatter, написанный не нами: кавычки, ISO-дата с T, отступ у списка,
# двоеточие внутри значения. Всё это YAML-round-trip переписывает по-своему.
HOSTILE = """---
id: ae1eb35e
apple_id: "x-coredata://87F91535/ICNote/p42"
title: "Задача по #12345"
created: 2020-11-23T15:17:01
summary: "Необходимо создать задачу: приёмка."
tags:
  - work/demo
  - trash_candidate
---

# Задача по #12345

Тело.

## Раздел

Содержимое.
"""


def test_create_note_stamps_id():
    """Заметка, рождённая через MCP, сразу несёт `id:` = sha1(путь)[:12],
    ту же формулу, что и `rename_note` при бэкфилле."""
    from vault_mcp.naming import note_id
    f = Fixture()
    try:
        f.v.create_note("Тест", "текст", folder="10_Notes")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/Тест.md"))
        check(data.get("id") == note_id("10_Notes/Тест.md"),
              "id новой заметки = note_id(её пути)")
        check(len(str(data.get("id"))) == 12, "id длиной 12 символов")
        # Свой id в переданном frontmatter не перезаписывается.
        f.v.create_note("Свой", "---\nid: zzz111\n---\nтекст", folder="10_Notes")
        data, _ = vaultops.split_frontmatter(f.read("10_Notes/Свой.md"))
        check(data.get("id") == "zzz111", "явный id из content сохранён")
        # Имя файла по правилу пайплайна (safe_stem): скобки и `:` уходят.
        out = f.v.create_note("Скобки [x]: да", "текст", folder="10_Notes")
        check("Скобки _x__ да.md" in out or (f.root / "10_Notes/Скобки _x__ да.md").exists(),
              f"имя файла по safe_stem: {out.splitlines()[0][:80]}")
    finally:
        f.close()


def test_body_edits_do_not_touch_frontmatter():
    """Правка тела не имеет права переформатировать чужой frontmatter.

    Прогон через yaml.safe_load/safe_dump снимает кавычки, превращает
    `2020-11-23T15:17:01` в `2020-11-23 15:17:01` и сдвигает отступы списка.
    Пользователь этого не просил, а diff в его хранилище получает он.
    """
    f = Fixture()
    try:
        fm_before = HOSTILE.split("---")[1]
        for label, call in (
            ("patch_note", lambda: f.v.patch_note("10_Notes/H.md", "Раздел", "дописка")),
            ("patch_note преамбула", lambda: f.v.patch_note("10_Notes/H.md", "", "верх", operation="prepend")),
            ("append_to_note", lambda: f.v.append_to_note("10_Notes/H.md", "хвост")),
            ("delete_section", lambda: f.v.delete_section("10_Notes/H.md", "Раздел")),
        ):
            f.write("10_Notes/H.md", HOSTILE)
            call()
            after = f.read("10_Notes/H.md")
            check(after.split("---")[1] == fm_before,
                  f"{label}: frontmatter байт в байт прежний")

        # Переименование frontmatter трогает, но ТОЛЬКО свои две строки.
        f.write("10_Notes/H.md", HOSTILE)
        f.v.rename_note("10_Notes/H.md", "Задача по №12345")
        after = f.read("10_Notes/Задача по №12345.md")
        fm_after = after.split("---")[1]
        changed = [ln for ln in fm_after.splitlines()
                   if ln and ln not in fm_before.splitlines()]
        check(changed == ["title: Задача по №12345"],
              f"переименование меняет только строку title: {changed}")
        check('apple_id: "x-coredata://87F91535/ICNote/p42"' in fm_after
              and "created: 2020-11-23T15:17:01" in fm_after
              and "  - work/demo" in fm_after,
              "кавычки, ISO-дата и отступ списка сохранены")
    finally:
        f.close()


def test_readonly_switch():
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        ro = Vault(f.root, inbox_rel="00_Inbox/daily", tz=timezone.utc, readonly=True)
        raises(lambda: ro.write_note("10_Notes/A.md", "x\n"), VaultError,
               "MCP_READONLY блокирует запись")
        check(ro.read_note("10_Notes/A.md") == NOTE, "чтение при MCP_READONLY работает")
    finally:
        f.close()


def test_per_user_policy():
    """Static-token accounts: `deny=` and `readonly` via the ContextVars the
    middleware sets; humans (empty policy) are untouched and their journal
    lines carry no `auth` key. Contract: docs/static-tokens.md."""
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        f.write("10_Notes/B.md", NOTE)
        tokens = (
            vaultops.CURRENT_USER.set("agent"),
            vaultops.CURRENT_AUTH.set("static"),
            vaultops.CURRENT_DENIED_TOOLS.set(frozenset({"delete_note"})),
        )
        try:
            exc = None
            try:
                f.v.delete_note("10_Notes/A.md")
            except VaultError as e:
                exc = e
            check(exc is not None and str(exc) == "tool 'delete_note' is denied for user 'agent'",
                  f"deny: delete_note отклонён с нужным текстом ({exc})")
            check((f.root / "10_Notes/A.md").is_file() and not (f.root / ".trash").exists(),
                  "deny: файл на месте, корзины нет")
            raises(lambda: f.v.delete_note("10_Notes/A.md", dry_run=True), VaultError,
                   "deny: dry_run тоже отклонён")
            raises(lambda: f.v.delete_note("10_Notes/A.md", permanent=True), VaultError,
                   "deny: permanent тоже отклонён")
            check((f.root / "10_Notes/A.md").is_file(), "deny: после трёх отказов файл цел")
            last = f.journal()[-1]
            check(last["ok"] is False and last["user"] == "agent" and last["auth"] == "static"
                  and last["tool"] == "delete_note", f"deny: отказ в журнале с user/auth/tool ({last})")
            out = f.v.create_note("Agent note", "body\n", folder="10_Notes")
            check(out.startswith("ok: create_note"), "deny: create_note агента проходит")
            check(f.journal()[-1].get("auth") == "static" and f.journal()[-1]["user"] == "agent",
                  "успешная запись агента атрибутирована auth: static")
            check(f.v.read_note("10_Notes/B.md") == NOTE, "deny: чтение работает")
        finally:
            vaultops.CURRENT_DENIED_TOOLS.reset(tokens[2])
            vaultops.CURRENT_AUTH.reset(tokens[1])
            vaultops.CURRENT_USER.reset(tokens[0])

        t_user = vaultops.CURRENT_USER.set("agent")
        t_den = vaultops.CURRENT_DENIED_TOOLS.set(frozenset({vaultops.READONLY_ALL}))
        try:
            exc = None
            try:
                f.v.write_note("10_Notes/B.md", "x\n")
            except VaultError as e:
                exc = e
            check(exc is not None and str(exc) == "server is read-only for user 'agent'",
                  f"readonly: текст отказа ({exc})")
            check(f.read("10_Notes/B.md") == NOTE, "readonly: файл не изменён")
            check(f.v.read_note("10_Notes/B.md") == NOTE, "readonly: чтение работает")
        finally:
            vaultops.CURRENT_DENIED_TOOLS.reset(t_den)
            vaultops.CURRENT_USER.reset(t_user)

        ro = Vault(f.root, inbox_rel="00_Inbox/daily", tz=timezone.utc, readonly=True)
        t_den = vaultops.CURRENT_DENIED_TOOLS.set(frozenset({"delete_note"}))
        try:
            exc = None
            try:
                ro.write_note("10_Notes/B.md", "x\n")
            except VaultError as e:
                exc = e
            check(exc is not None and "MCP_READONLY" in str(exc),
                  "глобальный MCP_READONLY действует и при политике без этого инструмента")
        finally:
            vaultops.CURRENT_DENIED_TOOLS.reset(t_den)

        # A human after the agent: nothing leaks between requests.
        t_user = vaultops.CURRENT_USER.set("alice")
        try:
            f.v.delete_note("10_Notes/B.md")
            last = f.journal()[-1]
            check(last["ok"] is True and last["user"] == "alice" and "auth" not in last,
                  "OAuth-пользователь удаляет, запись без ключа auth")
        finally:
            vaultops.CURRENT_USER.reset(t_user)
        check(vaultops.MUTATING_TOOLS >= {"create_note", "delete_note", "rename_note"},
              "MUTATING_TOOLS заполнен регистрациями _journaled")
    finally:
        f.close()


def test_code_fences_are_not_structure():
    """Строки '#' и '#тег' внутри код-блоков не заголовки и не теги.

    Аудит ponytail: delete_section по такому «заголовку» вырезал код-блок
    и хвост заметки, note_info показывал его в оглавлении, rename_note
    переписывал H1-образную строку внутри блока.
    """
    f = Fixture()
    try:
        f.write("10_Notes/A.md",
                "# A\n\n```python\n# Заг в коде\nx = 1  #тегвкоде\n```\n\n## Раздел\n\nтело\n")
        raises(lambda: f.v.delete_section("10_Notes/A.md", "Заг в коде"),
               NotFound, "заголовок в код-блоке не находится")
        raises(lambda: f.v.patch_note("10_Notes/A.md", "Заг в коде", "x",
                                      create_if_missing=False),
               NotFound, "patch_note не видит заголовок в код-блоке")
        check("Заг в коде" not in f.v.note_info("10_Notes/A.md"),
              "note_info не показывает код-блок в оглавлении")
        check(f.v.search_by_tag("тегвкоде") == "(no notes)",
              "тег внутри код-блока не находится")
        check("x = 1" in f.read("10_Notes/A.md"), "код-блок цел")

        f.write("10_Notes/Старое имя.md",
                "```bash\n# Старое имя в коде\n```\n\n# Старое имя\n")
        f.v.rename_note("10_Notes/Старое имя.md", "Новое имя")
        t = f.read("10_Notes/Новое имя.md")
        check("# Старое имя в коде" in t and "# Новое имя" in t,
              "rename переписывает настоящий H1 и не трогает код-блок")
    finally:
        f.close()


def test_nested_anchor_stays_in_subtree():
    """«Родитель::Потомок» не матчит сиблинга родителя.

    Аудит ponytail: в заметке с «## Alpha» и «## Beta» якорь Alpha::Beta
    вставлял текст в секцию Beta и отвечал ok.
    """
    f = Fixture()
    try:
        f.write("10_Notes/T.md", "# T\n\n## Alpha\n\na\n\n## Beta\n\nb\n")
        raises(lambda: f.v.patch_note("10_Notes/T.md", "Alpha::Beta", "вставка",
                                      create_if_missing=False),
               NotFound, "сиблинг родителя не матчится как вложенный якорь")
        check("вставка" not in f.read("10_Notes/T.md"), "текст не вставлен в чужую секцию")

        f.write("10_Notes/U.md", "# U\n\n## Alpha\n\n### Beta\n\nb\n\n## Gamma\n\ng\n")
        f.v.patch_note("10_Notes/U.md", "Alpha::Beta", "вставка")
        t = f.read("10_Notes/U.md")
        check(t.index("### Beta") < t.index("вставка") < t.index("## Gamma"),
              "настоящий вложенный якорь по-прежнему работает")
    finally:
        f.close()


def test_symlinks_are_invisible():
    """Симлинк внутри базы не открывает внешние файлы для листинга и поиска."""
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        outside = Path(f.tmp.name) / "outside.md"
        outside.write_text("секретный текст снаружи\n", encoding="utf-8")
        os.symlink(outside, f.root / "10_Notes" / "leak.md")
        check("10_Notes/leak.md" not in f.v.list_notes("10_Notes"),
              "симлинк не попадает в листинг")
        check("секретный" not in f.v.search_notes("секретный"),
              "поиск не читает внешнее через симлинк")
    finally:
        f.close()


def test_frontmatter_keys_with_dashes_rewrite():
    """Ключи frontmatter с дефисом, цифрами и заглавными переписываются."""
    f = Fixture()
    try:
        f.write("10_Notes/Старое имя.md",
                '---\nx-link: "Старое имя"\nurl2: Старое имя\n---\n\n# Старое имя\n')
        f.v.rename_note("10_Notes/Старое имя.md", "Новое имя")
        t = f.read("10_Notes/Новое имя.md")
        check('x-link: "Новое имя"' in t and "url2: Новое имя" in t,
              "скаляры с широким классом ключей переписаны")
    finally:
        f.close()


def test_oserror_becomes_vaulterror_and_is_journaled():
    """Ошибка ФС между проверкой и чтением: единая форма ERROR и строка журнала."""
    f = Fixture()
    try:
        f.write("10_Notes/A.md", NOTE)
        orig = f.v.read

        def boom(_p):
            raise FileNotFoundError("vanished between check and read")

        f.v.read = boom
        try:
            raises(lambda: f.v.write_note("10_Notes/A.md", "x\n"), VaultError,
                   "ошибка ФС отдаётся как VaultError (единая форма ERROR)")
        finally:
            f.v.read = orig
        last = f.journal()[-1]
        check(last["ok"] is False and "os error" in last.get("error", ""),
              f"отказ по ошибке ФС в журнале ({last.get('error', '')[:40]})")
    finally:
        f.close()


def test_inbox_and_trash_unique_stamps():
    """Два дропа и два удаления в одну секунду не конфликтуют."""
    f = Fixture()
    try:
        r1 = f.v.create_note("Дроп", "1")
        r2 = f.v.create_note("Дроп", "2")
        check(r1.startswith("ok:") and r2.startswith("ok:"),
              "два инбоксных дропа подряд создаются без коллизии")
        f.write("10_Notes/X.md", NOTE)
        f.write("10_Notes/Y.md", NOTE)
        f.v.delete_note("10_Notes/X.md")
        f.v.delete_note("10_Notes/Y.md")
        check(len(list((f.root / ".trash").glob("*.md"))) == 2,
              "в корзине оба файла, ничего не перезаписано")
    finally:
        f.close()


def test_atomic_write_concurrent_same_note():
    """Конкурентная запись одной заметки из одного процесса не роняет вызовы."""
    import threading

    f = Fixture()
    try:
        f.write("10_Notes/A.md", "# A\n")
        barrier = threading.Barrier(4)
        errors: list[str] = []

        def worker(i: int):
            barrier.wait()
            try:
                f.v.write_note("10_Notes/A.md", f"# A\n\n{i}\n")
            except Exception as exc:  # noqa: BLE001 — фиксируем любой краш
                errors.append(type(exc).__name__)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check(not errors, f"конкурентная запись без ошибок ({errors})")
        check(f.read("10_Notes/A.md").startswith("# A"), "файл после гонки цел")
        check(f.stray_temp_files() == [], "временных файлов не осталось")
    finally:
        f.close()


def main() -> int:
    for fn in (
        test_per_user_policy,
        test_create_note_refuses_existing,
        test_atomic_and_no_op_write,
        test_expected_hash,
        test_delete_note,
        test_delete_section,
        test_preamble_patch,
        test_dry_run,
        test_edit_frontmatter_canonical_int,
        test_rename_note,
        test_rename_pins_cache_identity,
        test_create_note_stamps_id,
        test_body_edits_do_not_touch_frontmatter,
        test_listing_fields_and_where,
        test_existing_tools_unchanged,
        test_readonly_switch,
        test_code_fences_are_not_structure,
        test_nested_anchor_stays_in_subtree,
        test_symlinks_are_invisible,
        test_frontmatter_keys_with_dashes_rewrite,
        test_oserror_becomes_vaulterror_and_is_journaled,
        test_inbox_and_trash_unique_stamps,
        test_atomic_write_concurrent_same_note,
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
