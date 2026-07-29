"""Deterministic startup and allowlist smoke for enabled project MCP servers."""

from __future__ import annotations

import argparse
import asyncio
import os
import tomllib
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[2]
PROJECT_SERVERS = ("arxiv", "context7", "serena")


async def probe(name: str, expected_tools: set[str], *, functional_serena: bool) -> None:
    launcher = ROOT / ".codex" / "mcp" / name / "run.cmd"
    parameters = StdioServerParameters(
        command="cmd.exe",
        args=["/d", "/c", str(launcher)],
        cwd=str(ROOT),
        env=dict(os.environ),
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            raw_names = {tool.name for tool in result.tools}
            missing = expected_tools - raw_names
            if missing:
                raise RuntimeError(f"{name}: missing configured tools: {sorted(missing)}")
            if name == "serena" and functional_serena:
                response = await session.call_tool(
                    "get_symbols_overview",
                    {
                        "relative_path": "project/presaga/provider/token_service.py",
                        "depth": 1,
                    },
                )
                output = "\n".join(getattr(item, "text", "") for item in response.content)
                if output.startswith("Error executing tool:") or "TokenService" not in output:
                    raise RuntimeError(f"serena functional query failed: {output}")
            print(
                f"{name}: PASS "
                f"(raw_server_tools={len(raw_names)}, client_allowlist={len(expected_tools)})"
            )


async def run(functional_serena: bool) -> None:
    with (ROOT / ".codex" / "config.toml").open("rb") as handle:
        config = tomllib.load(handle)
    for name in PROJECT_SERVERS:
        server = config["mcp_servers"][name]
        if not server.get("enabled", True):
            raise RuntimeError(f"{name}: expected enabled project server")
        await asyncio.wait_for(
            probe(
                name,
                set(server.get("enabled_tools", [])),
                functional_serena=functional_serena,
            ),
            timeout=180,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--functional-serena",
        action="store_true",
        help="Perform one read-only symbol query after the startup handshake.",
    )
    args = parser.parse_args()
    asyncio.run(run(args.functional_serena))


if __name__ == "__main__":
    main()
