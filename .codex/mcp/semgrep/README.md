# Semgrep MCP (installed, disabled)

Purpose: candidate static-analysis and security-review MCP. The CLI package is installed and
pinned, but the MCP is deliberately disabled until its startup dependency is acceptable.

- Source: `https://github.com/semgrep/semgrep`
- Pinned package: `semgrep==1.164.0`
- Approximate stars on 2026-07-28: 16.0k
- License: LGPL-2.1-or-later
- State: installed, configured, disabled

## Install or rebuild

From the repository root:

```powershell
python -m venv .codex\mcp\semgrep\.venv
.codex\mcp\semgrep\.venv\Scripts\python.exe -m pip install -r .codex\mcp\semgrep\requirements.txt
```

## Why disabled

With v1.164.0, an stdio list-tools smoke attempted to fetch the Semgrep authorization-server
metadata from `semgrep.dev` and exited when the request timed out. This makes the MCP unsuitable as
an always-on, local-only review dependency. The ordinary Semgrep CLI remains available inside the
environment, but it should only be invoked by a work package that defines rules, scope, and
evidence value.

Do not add a token URL or secret merely to make the status look green. Re-enable only after:

1. the pinned upstream release supports a bounded startup path acceptable to the project; or
2. a work package explicitly authorizes and documents the semgrep.dev dependency.

## Smoke before re-enabling

Run a list-tools handshake through `run.cmd`. It must start reliably, and its authentication and
data egress must be documented. Then set `enabled = true` in `.codex/config.toml`.

## Rollback

It is already disabled. The ignored `.venv` can be removed later after its absolute path is
reviewed.
