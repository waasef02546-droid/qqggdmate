# Serena MCP

Purpose: inspect symbols, references, implementations, declarations, patterns, and file
diagnostics without reading entire source files. This is the primary MCP enhancement for
token-efficient code review.

- Source: `https://github.com/oraios/serena`
- Pinned packages: `serena-agent==1.5.3`, `uv==0.11.32`
- Approximate stars on 2026-07-28: 27.1k
- License: MIT
- Authentication: none
- Context: built-in `codex`
- Client exposure: read-only semantic and diagnostic tools only

## Install or rebuild

From the repository root:

```powershell
python -m venv .codex\mcp\serena\.venv
.codex\mcp\serena\.venv\Scripts\python.exe -m pip install -r .codex\mcp\serena\requirements.txt
```

The existing environment was created by `uv` with an available Python 3.13 runtime. Either method
is acceptable if the pinned package installs. The central client allowlist is
`[mcp_servers.serena]` in `.codex/config.toml`.

`run.cmd` uses the Codex context, disables dashboards and usage reporting, activates this project,
places Serena's mutable state under the ignored local `state` directory, and makes the
environment-local `uv/uvx` available to the Python language-server launcher. `UV_CACHE_DIR` is also
kept under `state`, so the MCP does not depend on a writable user-profile cache. Codex's own file
and shell tools remain authoritative.

## Data and security

The selected tools analyze local repository source and do not require a remote account. The Serena
project is marked read-only and Codex receives a nine-tool read-only allowlist. Serena v1.5.3's raw
MCP handshake still advertises its wider 22-tool Codex-context set; therefore the checked-in Codex
allowlist is the authoritative exposure boundary, while `read_only: true` provides defense in
depth against direct edit calls.

## Smoke

Restart Codex and confirm `serena` appears in `codex mcp list`, and use `codex mcp get serena
--json` to verify the nine-tool allowlist. A raw list-tools handshake may report 22 upstream tools;
the Codex client must expose only the allowlist. Then resolve one known symbol and one reference
set without modifying files.

## Rollback

Set `enabled = false` in `.codex/config.toml`. The ignored `.venv` and `state` directories can be
removed later after path review.
