# Context7 MCP

Purpose: retrieve current, version-aware documentation for libraries used by the implementation.
It reduces guesses about APIs; it does not review PRE-SAGA security properties.

- Source: `https://github.com/upstash/context7`
- Pinned package: `@upstash/context7-mcp@3.2.5`
- Approximate stars on 2026-07-28: 59.9k
- License: MIT
- Authentication: optional `CONTEXT7_API_KEY`, intentionally not configured
- Exposed tools: `resolve-library-id`, `query-docs`

## Install or rebuild

From the repository root:

```powershell
npm.cmd install --prefix .codex\mcp\context7 --cache .codex\mcp\runtime\npm-cache
```

`package.json` and `package-lock.json` pin the dependency graph. The central client configuration
is `[mcp_servers.context7]` in `.codex/config.toml`; `run.cmd` starts the local Node entry point.

## Optional key

No token URL belongs in Codex settings for local stdio mode. The anonymous service is sufficient
until measured rate limits block work. If a key is later approved, store `CONTEXT7_API_KEY` as a
user secret or inject it through an environment-variable allowlist; never commit its value.

## Data and security

Library names and documentation questions are sent to Context7. Do not send repository secrets,
private source, unpublished paper passages, or experiment participant data.

## Smoke

Restart Codex, confirm `context7` appears in `codex mcp list`, then perform a list-tools handshake.
A functional check may resolve one public library and request a short API topic.

## Rollback

Set `enabled = false` in `.codex/config.toml`. The ignored `node_modules` and shared npm cache can
be removed later after path review.
