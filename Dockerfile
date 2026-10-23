# Obsidian vault MCP server (streamable HTTP, PrefectHQ FastMCP + OAuth).
# Minimal, auditable MCP over the vault's markdown files: no headless Obsidian.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Container semantics: the container's own network is the isolation boundary,
# so the server binds all interfaces here (the bare-metal default stays
# 127.0.0.1; docker-compose.yml also sets this explicitly).
ENV MCP_HOST=0.0.0.0

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The package is copied whole; a stray file outside it cannot sneak into the
# image, and a forgotten module fails at import instead of at runtime.
COPY vault_mcp/ ./vault_mcp/

EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-u", "-m", "vault_mcp"]
