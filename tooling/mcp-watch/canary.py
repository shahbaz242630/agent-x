"""6E4 (MCP-Guide section 7): the daily real-client canaries written in Python.

Each one is a real client, pinned with hashes in requirements.txt (installed in
the workflow's own virtual environment, never in the image), against staging's
MCP endpoint with the smoke agent's key. It connects, lists the tools and calls
get_agent, and writes what it saw as a report for canary-judge.ts, which judges
every canary the same way. No model is called and no model key is needed.

    python canary.py python-legacy | python-auto | openai-agents REPORT.json

- python-legacy: the official Python SDK, the 2025 `initialize` handshake;
- python-auto: the same SDK's own negotiation (`server/discover`, falling back),
  the mode Hermes Agent uses;
- openai-agents: OpenAI's Agents SDK's MCPServerStreamableHttp, tools only.

The address comes in AGENTX_MCP_ORIGIN and the key in AGENTX_MCP_KEY. The key is
only ever a header; the report holds no address and no key (canary-judge.ts
blanks any key a client's error text repeats).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from importlib.metadata import version
from typing import Any

MCP_PATH = "/v1/mcp"
STEP_SECONDS = 60
CLIENT = {"name": "agent-x-canary", "version": "1"}


def _report(canary: str, client: str) -> dict[str, Any]:
    return {"canary": canary, "client": client, "version": version(client)}


def _agent(result: Any) -> dict[str, Any]:
    return {"isError": bool(result.is_error), "structuredContent": result.structured_content}


async def _official(url: str, key: str, mode: str, report: dict[str, Any]) -> None:
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client
    from mcp_types import Implementation

    report["step"] = "connect"
    async with create_mcp_http_client(headers={"Authorization": f"Bearer {key}"}) as http:
        async with Client(
            streamable_http_client(url, http_client=http),
            mode=mode,
            client_info=Implementation(**CLIENT),
            read_timeout_seconds=STEP_SECONDS,
        ) as client:
            report["protocol"] = client.protocol_version
            report["step"] = "list the tools"
            report["tools"] = [tool.name for tool in (await client.list_tools()).tools]
            report["step"] = "call get_agent"
            report["agent"] = _agent(await client.call_tool("get_agent", {}))


async def _openai_agents(url: str, key: str, report: dict[str, Any]) -> None:
    from agents.mcp import MCPServerStreamableHttp

    report["step"] = "connect"
    server = MCPServerStreamableHttp(
        params={"url": url, "headers": {"Authorization": f"Bearer {key}"}, "timeout": STEP_SECONDS},
        name="agentx",
        client_session_timeout_seconds=STEP_SECONDS,
    )
    async with server:
        report["step"] = "list the tools"
        report["tools"] = [tool.name for tool in await server.list_tools()]
        report["step"] = "call get_agent"
        report["agent"] = _agent(await server.call_tool("get_agent", {}))


CANARIES = {
    "python-legacy": ("mcp", lambda url, key, report: _official(url, key, "legacy", report)),
    "python-auto": ("mcp", lambda url, key, report: _official(url, key, "auto", report)),
    "openai-agents": ("openai-agents", _openai_agents),
}


def _error_text(error: BaseException) -> str:
    """An error's words, the first of a group's (anyio wraps a task's failure in one)."""
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return f"{type(error).__name__}: {error}"


def run(canary: str, url: str, key: str) -> dict[str, Any]:
    """One canary's report: what it saw, or where it stopped and the client's words."""
    client, body = CANARIES[canary]
    report = _report(canary, client)
    try:
        asyncio.run(body(url, key, report))
    except BaseException as error:  # noqa: BLE001 - every failure is the canary's finding, judged red
        if isinstance(error, KeyboardInterrupt):
            raise
        report["failed"] = {"step": report.get("step", "connect"), "error": _error_text(error)}
    report.pop("step", None)
    return report


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in CANARIES:
        print(f"usage: canary.py {' | '.join(CANARIES)} REPORT.json", file=sys.stderr)
        return 2
    canary, out = argv
    origin = os.environ.get("AGENTX_MCP_ORIGIN", "").rstrip("/")
    key = os.environ.get("AGENTX_MCP_KEY", "").strip()
    if not origin or not key:
        report = {**_report(canary, CANARIES[canary][0]), "failed": {"step": "connect", "error": "no address or key set"}}
    else:
        report = run(canary, f"{origin}{MCP_PATH}", key)
    with open(out, "w", encoding="utf-8") as file:
        json.dump(report, file)
    # Judged by canary-judge.ts; this only says it ran.
    print(f"{canary}: report written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
