"""obsidian-vault-mcp: an MCP server over an Obsidian vault's markdown files.

Layout of the package (each module owns one concern):

- ``server.py``        auth (OAuth + static tokens) and the thin ``@mcp.tool``
                       wrappers; the tool docstrings are the contract the
                       model reads;
- ``vaultops.py``      every filesystem operation, free of fastmcp imports
                       so it runs in offline tests;
- ``static_tokens.py`` the hash-file store for machine-account tokens;
- ``naming.py``        filesystem-safe note naming and note identity.
"""
__version__ = "1.0.0"
