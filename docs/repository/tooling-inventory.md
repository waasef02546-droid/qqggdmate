# Codex tooling inventory

- Inventory date: `2026-07-28`
- User Codex home: `C:\Users\asus\.codex`
- Project configuration: `.codex/config.toml`
- Detailed MCP manifests and setup guides: `.codex/mcp/`

State terms:

1. **installed**: package/runtime exists on disk;
2. **configured**: a Codex config declares it;
3. **enabled**: Codex will start it;
4. **runtime-verified**: an initialize/list-tools or functional smoke succeeded.

## MCP servers

| Name | Scope | Pinned version | State | Authentication | Enhancement |
|---|---|---:|---|---|---|
| `openaideveloperdocs` | global HTTP | managed | enabled, runtime-visible | none | Official OpenAI/Codex documentation |
| `node_repl` | global stdio | desktop-managed | enabled, runtime-visible | local runtime | Persistent JavaScript orchestration |
| `arxiv` | project stdio | 0.5.0 | enabled, handshake verified | none | Paper search, abstracts, citation graph |
| `context7` | project stdio | 3.2.5 | enabled, handshake verified | optional key absent | Version-aware library documentation |
| `serena` | project stdio | 1.5.3 | enabled, functional symbol query verified | none | Token-efficient symbol/reference/diagnostic review |
| `semgrep` | project stdio | 1.164.0 | installed and configured, disabled | startup requests semgrep.dev metadata | Static-analysis candidate |

Configured total: **6**; active total: **5**; repository limit: **10**.

Serena is constrained twice: `.serena/project.yml` sets read-only project scope, while
`.codex/config.toml` exposes only nine review tools. Serena v1.5.3 still advertises 22 upstream
Codex-context tools in a raw handshake, so the Codex client allowlist is the authoritative
exposure boundary.

Semgrep is not reported as active: its pinned MCP attempted to retrieve semgrep.dev OAuth metadata
even for stdio startup and exited when that dependency timed out. No token URL or secret was added
to hide this limitation.

The official GitHub MCP was deliberately not installed. The runtime-visible GitHub plugin already
covers repositories, pull requests, review comments, Actions diagnostics, and publication; a second
GitHub MCP would duplicate credentials and tool schemas.

## Skills

### Repository-specific

| Skill | State | Enhancement |
|---|---|---|
| `presaga-paper-grade` | installed and runtime-visible | Work-package discipline, core-code priority, impact-driven retest, acceptance/evidence closure |

The skill is intentionally concise because it routes durable repository rules and evidence policy;
it is not a cryptographic library. GitHub stars are not meaningful for a private repository rule
package.

### System and plugin skills visible in this session

- Codex/system: `openai-docs`, `skill-creator`, `skill-installer`, `plugin-creator`, `imagegen`
- Engineering/GitHub: `github`, `gh-address-comments`, `gh-fix-ci`, `yeet`
- Artifacts: `pdf`, `documents`, `spreadsheets`, `presentations`, `template-creator`
- Interaction/build: `browser`, `computer-use`, `sites-building`, `sites-hosting`, `visualize`

These are used on demand. They are not all repository-installed packages and must not be counted as
project MCP servers.

## Installed and enabled plugins

The desktop/runtime reports the following plugin-enhanced capabilities available in this session:

- GitHub review, issue/PR context, CI diagnosis, and controlled publication
- PDF/paper inspection and rendered verification
- Document, spreadsheet, presentation, and template artifacts
- Browser/computer interaction
- Website building/hosting and interactive visualization

## Configuration and recovery

- `CODEX_HOME=C:\Users\asus\.codex` aligns the CLI with the desktop user's global MCP config.
- Project MCP configuration is centralized in `.codex/config.toml`.
- Each installed project MCP has its own README, pinned dependency file, launcher, data boundary,
  smoke procedure, and rollback procedure under `.codex/mcp/<name>/`.
- Runtime environments, downloads, indexes, and caches are ignored by Git.
- Restart Codex after changing MCP configuration.
