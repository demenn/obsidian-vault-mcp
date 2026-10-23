# obsidian-vault-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-supported-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![MCP](https://img.shields.io/badge/MCP-server-8A2BE2)](https://modelcontextprotocol.io)

MCP-сервер для работы с хранилищем Obsidian на сервере. Работает напрямую с markdown-файлами на диске: запущенный Obsidian не нужен, headless-режим не нужен, хранилище не отдается стороннему облаку. Транскрибация YouTube встроена: ссылка на видео превращается в конспект в том же хранилище.

[English version](README.en.md)

## Зачем он нужен

Для доступа ваших агентов к хранилищу Obsidian, которое хранится не локально, а на сервере. Работайте со своей базой в связке с ИИ-агентом откуда угодно: найти по слову, прочитать заметку, дописать раздел, посмотреть обратные ссылки. Хранилище попадает на сервер целиком привычной синхронизацией (Obsidian Sync, Syncthing, git), сервер открывает к нему доступ по MCP и при этом:

- **весь код читается за вечер**: один компактный пакет, никакой магии, никаких сторонних сервисов между агентом и вашими файлами;
- **запись безопасна**: атомарные записи, проверка конфликтов, холостой режим с diff, корзина вместо удаления, журнал каждой правки (подробнее в [docs/write-contract.md](docs/write-contract.md));
- **вход только ваш**: OAuth через GitHub или Google плюс список разрешенных логинов, пустой список не пускает никого. Для машинных учетных записей (агентов без браузера) есть предвыданные токены с политикой «что нельзя» (подробнее в [docs/static-tokens.md](docs/static-tokens.md));
- **видео → конспект**: транскрибация YouTube встроена в сервер, отдельный сервер расшифровок не нужен. Агент получает по ссылке расшифровку с названием и каналом и кладет конспект в базу.

Сервер отдает только `.md`-файлы и только внутри указанной папки базы: путь наружу базы невозможен, картинки и конфиги Obsidian не трогаются.

## Инструменты (15)

| Чтение | Запись |
|---|---|
| `list_notes` (листинг, фильтры по frontmatter) | `create_note` (создать, дубликат это ошибка) |
| `search_notes` (подстрочный поиск со сниппетом) | `write_note` (перезаписать целиком) |
| `read_note` | `append_to_note` (дописать в конец) |
| `note_info` (размер, mtime, sha256, оглавление) | `patch_note` (правка секции по заголовку) |
| `search_by_tag` (frontmatter и inline #теги) | `edit_frontmatter` (поле YAML: set/append/delete) |
| `get_backlinks` (кто ссылается на заметку) | `delete_section` (убрать заголовок с телом) |
| | `delete_note` (в `.trash/`, обратимо) |
| | `rename_note` (с переписыванием всех входящих ссылок) |

## Дополнительный инструмент `youtube_transcript`

Отдает расшифровку видео с названием и каналом. Работоспособность зависит от того, на каком сервере хостится MCP. YouTube обычно не отдает транскрипт запросам с IP-адресов хостингов. С домашнего или офисного адреса работает, с адреса арендованного сервера (VPS) вероятны отказы; исходящий трафик можно направить через прокси переменной `HTTPS_PROXY`.

## Структура

```
vault_mcp/            код сервера (пакет)
  server.py           вход, OAuth, обертки @mcp.tool
  vaultops.py         вся работа с файлами базы
  static_tokens.py    файл хешей машинных токенов
  naming.py           безопасные имена заметок
tests/                офлайн-тесты (без сети и fastmcp)
tools/                выдача токена, пробник приемки
docs/                 контракт записи, токены, подключение клиента
Dockerfile, docker-compose.yml, .env.example   деплой
```

## Быстрый старт

Нужен сервер с Docker и домен с HTTPS (OAuth требует публичный адрес). Рядом с базой, за своим reverse-proxy (Caddy, Traefik, nginx, что угодно).

```bash
git clone https://github.com/demenn/obsidian-vault-mcp.git
cd obsidian-vault-mcp
cp .env.example .env
# заполнить: OAuth-ключи, MCP_BASE_URL, MCP_ALLOWED_USERS, HOST_VAULT
docker compose up -d --build
```

Как создать OAuth-приложение и заполнить `.env`: комментарии внутри [.env.example](.env.example).

Проверка, что сервер жив (одна строка; любой HTTP-код в ответе значит «жив», отказ соединения значит «не поднялся»):

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://your-domain/mcp
# 401 = вход включен и закрыт, как задумано; 406 = OAuth еще не настроен
```

Подключение в Claude: Settings, Connectors, Add custom connector, URL `https://your-domain/mcp`. Для любого другого клиента и для машинных токенов: [docs/connecting-a-client.md](docs/connecting-a-client.md).

Без Docker: `pip install .` из папки репозитория, затем `vault-mcp` (переменные окружения те же, список в [.env.example](.env.example)).

## Переменные окружения

Основные (полный список с пояснениями в [.env.example](.env.example)):

| Переменная | Смысл |
|---|---|
| `VAULT_PATH` | путь к базе внутри контейнера (по умолчанию `/vault`) |
| `VAULT_INBOX_REL` | папка, куда `create_note` кладет заметки без явного адреса |
| `VAULT_EXCLUDE_DIRS` | папки, скрытые от листинга и поиска, через запятую |
| `MCP_HOST` | адрес, на котором слушает сервер (по умолчанию `127.0.0.1`; compose ставит `0.0.0.0` за reverse-proxy) |
| `MCP_BASE_URL` | публичный HTTPS-адрес сервера, нужен для OAuth |
| `MCP_AUTH_PROVIDER` | `github` (по умолчанию) или `google` |
| `MCP_ALLOWED_USERS` | кому разрешен вход (логины GitHub или письма Google) |
| `MCP_JWT_SIGNING_KEY` | ключ подписи клиентских токенов, логины переживают рестарт |
| `MCP_STATIC_TOKENS_FILE` | файл хешей машинных токенов, опционально |
| `MCP_READONLY` | `true` = запретить все пишущие инструменты |
| `MCP_LOG_DIR` | каталог журналов (`mcp-writes.jsonl`, `mcp-auth.jsonl`) |

## Тесты

Офлайн, без сети и без fastmcp (нужен только pyyaml), подойдет любой Python 3.9+:

```bash
pip install pyyaml
python3 tests/test_vaultops.py
python3 tests/test_static_tokens.py
```

Линтер: `ruff check .` (конфиг в `ruff.toml`).

## Документация

- [docs/write-contract.md](docs/write-contract.md): контракт записи (атомарность, `expected_hash`, `dry_run`, корзина, журнал, модель угроз)
- [docs/static-tokens.md](docs/static-tokens.md): машинные токены: выдача, ротация, политика «что нельзя»
- [docs/connecting-a-client.md](docs/connecting-a-client.md): подключение клиента по токену, curl, разбор отказов

## Лицензия

[MIT](LICENSE)
