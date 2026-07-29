# ArXiv MCP

Purpose: search ArXiv, retrieve abstracts, and inspect citation graphs without giving the server
write access to the repository. It is not a substitute for reading the full paper or checking a
claim against the cited source.

- Source: `https://github.com/blazickjp/arxiv-mcp-server`
- Pinned version: `0.5.0`
- Approximate stars on 2026-07-28: 3.0k
- License: Apache-2.0
- Authentication: none
- Exposed tools: `search_papers`, `get_abstract`, `citation_graph`

## Install or rebuild

From the repository root:

```powershell
python -m venv .codex\mcp\arxiv\.venv
.codex\mcp\arxiv\.venv\Scripts\python.exe -m pip install -r .codex\mcp\arxiv\requirements.txt
```

The central client configuration is `[mcp_servers.arxiv]` in `.codex/config.toml`; `run.cmd`
sets the local paper/index cache path and starts stdio transport.

## Data and security

Queries and paper identifiers are sent to services used by the upstream package, including ArXiv
and citation metadata services when the selected tool requires them. Do not include private code,
credentials, unpublished text, or participant data in queries. Downloads and indexes stay in the
ignored `cache` directory.

## Smoke

Restart Codex, confirm `arxiv` appears in `codex mcp list`, then perform a list-tools handshake.
For a network functional check, search for one public paper title and record the query only when it
is part of an evidence-producing work package.

## Rollback

Set `enabled = false` in `.codex/config.toml`. The ignored `.venv` and `cache` directories can be
removed later after their absolute paths are reviewed; the configuration and documentation remain
reproducible.
