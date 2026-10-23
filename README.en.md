# obsidian-vault-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-supported-2496ED?logo=docker&logoColor=white)](Dockerfile)
[![MCP](https://img.shields.io/badge/MCP-server-8A2BE2)](https://modelcontextprotocol.io)

An MCP server (Model Context Protocol, the standard for plugging external tools into an AI agent) for working with an Obsidian vault on a server. It works directly with the vault's markdown files on disk: no running Obsidian, no headless mode, no third-party cloud between the agent and your files. YouTube transcription is built in: a video link turns into a note in the same vault.

[Русская версия](README.md)

## Why

Gives your agents access to an Obsidian vault stored not on a local machine but on a server. Work on your knowledge base together with an AI agent from anywhere: search by word, read a note, append a section, look at backlinks. The vault reaches the server in full through your usual sync (Obsidian Sync, Syncthing, git); the server opens access over MCP, and:

- **the code reads in one evening**: one small package, no magic, no external services;
- **writes are safe**: atomic writes, conflict detection (`expected_hash`), dry runs with diffs, a `.trash/` folder instead of deletion, and a JSONL audit journal (see [docs/write-contract.md](docs/write-contract.md), in Russian);
- **only you get in**: GitHub or Google OAuth plus an allow-list (an empty list admits nobody). Machine accounts (agents with no browser) use pre-issued tokens with a per-account "what is denied" policy (see [docs/static-tokens.md](docs/static-tokens.md), in Russian);
- **video → note**: YouTube transcription is built into the server, so no separate transcript server is needed. The agent fetches the transcript for a link, with the video title and channel, and files the summary as a note.

The server touches `.md` files only, and only inside the configured vault root: paths cannot escape it.

## Tools (15)

| Reading | Writing |
|---|---|
| `list_notes` (listing, frontmatter filters) | `create_note` (new note; a duplicate path is an error) |
| `search_notes` (substring search with snippets) | `write_note` (full overwrite) |
| `read_note` | `append_to_note` |
| `note_info` (size, mtime, sha256, outline) | `patch_note` (edit a section by heading) |
| `search_by_tag` (frontmatter and inline #tags) | `edit_frontmatter` (YAML field: set/append/delete) |
| `get_backlinks` | `delete_section` (heading plus body) |
| | `delete_note` (into `.trash/`, reversible) |
| | `rename_note` (rewrites every incoming wikilink) |

## Additional tool `youtube_transcript`

Returns a video transcript with the title and channel. Whether it works depends on which server hosts the MCP. YouTube usually refuses transcripts to requests coming from hosting (datacenter) IP addresses. From a home or office address it works; from a rented server (VPS) refusals are likely. Outgoing requests can be routed through a proxy with the `HTTPS_PROXY` variable.

## Structure

```
vault_mcp/            server code (the package)
  server.py           entry point, OAuth, thin @mcp.tool wrappers
  vaultops.py         all vault file operations
  static_tokens.py    machine-token hash file
  naming.py           safe note names
tests/                offline tests (no network, no fastmcp)
tools/                token issuing, acceptance probe
docs/                 write contract, tokens, connecting a client
Dockerfile, docker-compose.yml, .env.example   deployment
```

## Quick start

A server with Docker and an HTTPS domain (OAuth needs a public URL), behind your own reverse proxy.

```bash
git clone https://github.com/demenn/obsidian-vault-mcp.git
cd obsidian-vault-mcp
cp .env.example .env   # fill in OAuth keys, MCP_BASE_URL, MCP_ALLOWED_USERS, HOST_VAULT
docker compose up -d --build
```

OAuth app setup notes are inside [.env.example](.env.example).

A liveness check (one line; any HTTP code in the answer means "alive", a connection refusal means the server did not start):

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://your-domain/mcp
# 401 = auth is on and locked, as intended; 406 = OAuth is not configured yet
```

In Claude: Settings, Connectors, Add custom connector, URL `https://your-domain/mcp`. Any other HTTP MCP client works too; for machine tokens see [docs/connecting-a-client.md](docs/connecting-a-client.md). Without Docker: `pip install .` from the repository folder, then `vault-mcp` (same environment variables, the full list in [.env.example](.env.example)).

## Environment variables

The main ones (full list with explanations in [.env.example](.env.example)):

| Variable | Meaning |
|---|---|
| `VAULT_PATH` | vault path inside the container (default `/vault`) |
| `VAULT_INBOX_REL` | folder where `create_note` puts notes without an explicit address |
| `VAULT_EXCLUDE_DIRS` | folders hidden from listing and search, comma-separated |
| `MCP_HOST` | address the server listens on (default `127.0.0.1`; compose sets `0.0.0.0` behind a reverse proxy) |
| `MCP_BASE_URL` | public HTTPS address of the server, needed for OAuth |
| `MCP_AUTH_PROVIDER` | `github` (default) or `google` |
| `MCP_ALLOWED_USERS` | who is allowed in (GitHub logins or Google emails) |
| `MCP_JWT_SIGNING_KEY` | client-token signing key; logins survive a restart |
| `MCP_STATIC_TOKENS_FILE` | machine-token hash file, optional |
| `MCP_READONLY` | `true` = forbid every writing tool |
| `MCP_LOG_DIR` | log directory (`mcp-writes.jsonl`, `mcp-auth.jsonl`) |

## Tests

Offline, no network, no fastmcp (only pyyaml):

```bash
pip install pyyaml
python3 tests/test_vaultops.py
python3 tests/test_static_tokens.py
```

## Documentation

- [docs/write-contract.md](docs/write-contract.md): the write contract (atomicity, `expected_hash`, `dry_run`, trash, journal, threat model)
- [docs/static-tokens.md](docs/static-tokens.md): machine tokens: issuing, rotation, the "what is denied" policy
- [docs/connecting-a-client.md](docs/connecting-a-client.md): connecting a client with a token, curl, decoding refusals

The docs are written in Russian; an English translation can be added on request (issues welcome).

## License

[MIT](LICENSE)
