# PRE-SAGA repository MCP tools

This directory contains pinned, repository-scoped MCP launchers and setup notes. Runtime
environments, downloaded papers, indexes, and caches are ignored by Git.

## Inventory

| MCP | State | Main use | Authentication |
|---|---|---|---|
| `openaideveloperdocs` | active, global | Official OpenAI and Codex documentation | none |
| `node_repl` | active, global | Persistent JavaScript orchestration | local runtime |
| `arxiv` | active, project | Paper discovery, abstracts, citation graph | none |
| `context7` | active, project | Version-aware library documentation | optional API key, not configured |
| `serena` | active, project | Token-efficient symbol and reference review | none |
| `semgrep` | installed, disabled | Static-analysis MCP candidate | startup currently requires semgrep.dev metadata |

Configured total: **6**. Active total: **5**. The repository limit is 10.

Exact versions, source URLs, sampled GitHub stars, licenses, and status reasons are recorded in
`inventory.yaml`. Each project MCP subdirectory contains its own install, configuration, smoke,
data-flow, and rollback instructions.

## Configuration model

- `.codex/config.toml` is the single project MCP configuration.
- Each project server is launched through a checked-in `run.cmd`.
- Python packages use an ignored `.venv`; Node packages use ignored `node_modules`.
- Direct dependencies are pinned. Context7 also has a generated `package-lock.json`.
- No token URL is required for these stdio servers. Do not invent one.
- `CONTEXT7_API_KEY` is optional and intentionally absent. Add it only as a user-level secret if
  rate limits become a measured blocker.
- Restart Codex after changing MCP configuration so the session reloads the tool list.

## Why only these tools

Popularity was used as a maintenance signal, not as the sole decision rule. The installed set also
had to be relevant, bounded, reproducible on Windows, and non-duplicative.

- The official GitHub MCP server was not added because the current GitHub plugin already provides
  repository, pull-request, review-comment, and CI workflows. Adding a second GitHub surface would
  duplicate credentials and tools.
- `paper-search-mcp` was not added because its broad provider set overlaps ArXiv and introduces
  additional credentials and optional sources that are unsuitable for a clean reproducibility
  baseline.
- Semgrep remains disabled until its stdio startup works without a mandatory external OAuth
  metadata dependency or the project explicitly authorizes that dependency.

## Rebuild all project runtimes

Run the install commands from each subdirectory README. Never commit `.venv`, `node_modules`,
`cache`, or `state`.

## Verification

Use:

```powershell
$env:CODEX_HOME = 'C:\Users\asus\.codex'
codex mcp list
```

Then run the deterministic project smoke:

```powershell
.codex\mcp\arxiv\.venv\Scripts\python.exe .codex\mcp\check_servers.py --functional-serena
```

The command initializes ArXiv, Context7, and Serena, checks that every Codex-allowlisted tool is
advertised, and performs one read-only Serena symbol query. A handshake proves startup and tool
exposure; it does not prove the correctness of a paper result or source-code finding.
