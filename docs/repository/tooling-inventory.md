# Codex tooling inventory

- Work package: `CFG-002`
- Inventory date: `2026-07-28`
- User Codex home: `C:\Users\asus\.codex`
- Project config: `.codex/config.toml`

This inventory distinguishes four states that must not be conflated:

1. **on disk** — files or caches exist;
2. **configured** — a config file declares the capability;
3. **enabled** — the plugin/MCP manager reports it enabled;
4. **runtime-visible** — the current Codex session can actually invoke it.

## MCP servers

| Name | Transport | Configured location | Authentication | Runtime result | Capability |
|---|---|---|---|---|---|
| `openaideveloperdocs` | Streamable HTTP | `C:\Users\asus\.codex\config.toml` | None; no bearer token or token URL | Visible when `CODEX_HOME=C:\Users\asus\.codex` | Official OpenAI/Codex documentation search and retrieval |
| `node_repl` | Local stdio | `C:\Users\asus\.codex\config.toml` | Local desktop runtime | Visible when `CODEX_HOME=C:\Users\asus\.codex` | Persistent JavaScript orchestration and browser-control support |

The Spreadsheets runtime may expose document-control MCP tools dynamically. Those are
plugin-provided session tools, not manually configured entries in `config.toml`.

### Resolved CLI mismatch

The managed Codex shell resolves its profile as `C:\Users\CodexSandboxOffline`, while the actual
desktop/user configuration is under `C:\Users\asus\.codex`. Without `CODEX_HOME`, `codex mcp list`
therefore inspected an empty config root and incorrectly appeared to show no MCP servers.

`CODEX_HOME=C:\Users\asus\.codex` was persisted for the actual Windows user during `CFG-002`.
New PowerShell/Codex processes should inherit it; already-open terminals must be restarted. With the
variable supplied explicitly, both installed CLI versions list the two MCP servers above.

Verification:

```powershell
[Environment]::GetFolderPath('UserProfile')
$env:CODEX_HOME
codex --version
codex mcp list
```

Do not copy `node_repl` into the repository config. Its command, runtime version, and native-pipe
environment are desktop-local and non-portable.

## Skills

### Repository skill

| Skill | State | Purpose |
|---|---|---|
| `presaga-paper-grade` | on disk and runtime-visible | Bounded PRE-SAGA core work packages, impact-based verification, acceptance gates, and evidence closure |

The project skill is intentionally small because it is an orchestration layer, not a PRE library.
It consists of:

- `SKILL.md` — workflow and routing;
- `references/acceptance-gates.md` — paper-grade gates;
- `references/retest-policy.md` — impact-based retest rules;
- `scripts/check_repo_workflow.py` — deterministic control-plane check.

GitHub stars are not a meaningful selection criterion for repository-specific instructions. A
third-party cryptographic library, benchmark framework, or formal verifier should be evaluated in a
separate tool-selection work package using protocol fit, maintained releases, reproducibility,
security review, and paper acceptance—not stars alone.

### Global system skills on disk

- `imagegen`
- `openai-docs`
- `plugin-creator`
- `review-agent` — on disk but not exposed in the current session
- `skill-creator`
- `skill-installer`

## Installed and enabled plugins

The CLI plugin manager reports these nine plugins installed and enabled:

| Plugin | Main enhancement |
|---|---|
| `documents` | Create, edit, render, and verify Word documents |
| `pdf` | Read, render, inspect, and create PDFs |
| `spreadsheets` | Build and verify spreadsheet artifacts; optional live Excel control |
| `presentations` | Create and inspect slide decks |
| `template-creator` | Build reusable artifact templates |
| `browser` | Control the in-app browser |
| `computer-use` | Control Windows applications |
| `sites` | Build and deploy websites |
| `visualize` | Create interactive visualizations |

GitHub skills are present in the plugin cache and runtime-visible in this Codex session, but the CLI
plugin registry does not report the GitHub plugin as installed. It must therefore be described as
**runtime-visible**, not as a confirmed installed plugin.

## Installation policy

- Do not install a tool merely because it is popular or may become useful.
- Prefer the official Docs MCP for OpenAI/Codex questions.
- Use the PDF plugin for the target paper and paper artifact inspection.
- Add GitHub connectivity only when a work package actually publishes or reviews repository state.
- Evaluate PRE/crypto/formal-verification tools inside their own authorized work package.
- Update this inventory whenever configured, enabled, or runtime-visible state changes.
