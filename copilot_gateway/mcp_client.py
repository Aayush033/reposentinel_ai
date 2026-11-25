"""MCP client manager: connects to both Synapse-generated MCP servers via stdio."""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import Tool

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe")


@dataclass
class MCPToolInfo:
    server_name: str
    tool: Tool


@dataclass
class MCPServerStatus:
    name: str
    status: str = "disconnected"
    error: str | None = None
    tools: list[Tool] = field(default_factory=list)
    last_refreshed_at: str | None = None


class MCPClientManager:
    """Manages stdio connections to both Synapse-generated MCP servers.

    Tools are discovered dynamically by calling list_tools() on each session.
    The tool registry is never hardcoded.
    """

    def __init__(self) -> None:
        self._github_status = MCPServerStatus(name="github-service-mcp")
        self._osv_status = MCPServerStatus(name="osv-service-mcp")
        self._tool_registry: dict[str, MCPToolInfo] = {}
        self._last_refreshed_at: str | None = None

    @property
    def github_status(self) -> MCPServerStatus:
        return self._github_status

    @property
    def osv_status(self) -> MCPServerStatus:
        return self._osv_status

    @property
    def tool_registry(self) -> dict[str, MCPToolInfo]:
        return self._tool_registry

    @property
    def last_refreshed_at(self) -> str | None:
        return self._last_refreshed_at

    def _server_params(
        self, server_name: str, script_path: str
    ) -> StdioServerParameters:
        env = dict(os.environ)
        if server_name == "github-service-mcp":
            base_url = os.getenv("GITHUB_SERVICE_URL", "http://127.0.0.1:8001")
            env["GITHUB_SERVICE_BASE_URL"] = base_url
            env["ENDPOINT_BASE_URL"] = base_url
        else:
            base_url = os.getenv("OSV_SERVICE_URL", "http://127.0.0.1:8002")
            env["OSV_SERVICE_BASE_URL"] = base_url
            env["ENDPOINT_BASE_URL"] = base_url
        return StdioServerParameters(
            command=PYTHON_EXE,
            args=[script_path],
            env=env,
            cwd=str(PROJECT_ROOT),
        )

    async def _discover_tools_from_server(
        self,
        server_name: str,
        script_path: str,
        status: MCPServerStatus,
        timeout: float = 20.0,
    ) -> list[MCPToolInfo]:
        """Open a stdio session, initialize, call list_tools(), and close cleanly."""
        params = self._server_params(server_name, script_path)
        discovered: list[MCPToolInfo] = []
        try:
            async with asyncio.timeout(timeout):
                async with stdio_client(params) as (read_stream, write_stream):  # noqa: SIM117
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        result = await session.list_tools()
                        for tool in result.tools or []:
                            discovered.append(
                                MCPToolInfo(server_name=server_name, tool=tool)
                            )
            status.status = "connected"
            status.error = None
        except TimeoutError:
            status.status = "timeout"
            status.error = f"Server {server_name} did not respond within {timeout}s"
        except Exception as exc:  # noqa: BLE001
            status.status = "error"
            status.error = f"{type(exc).__name__}: {exc}"
        return discovered

    async def refresh_tools(self) -> dict[str, MCPToolInfo]:
        """Reconnect to both MCP servers and rebuild the dynamic tool registry."""
        from datetime import UTC, datetime

        github_script = str(PROJECT_ROOT / "github_service" / "synapse_auto_server.py")
        osv_script = str(PROJECT_ROOT / "osv_service" / "synapse_auto_server.py")

        github_tools, osv_tools = await asyncio.gather(
            self._discover_tools_from_server(
                "github-service-mcp", github_script, self._github_status
            ),
            self._discover_tools_from_server(
                "osv-service-mcp", osv_script, self._osv_status
            ),
        )

        self._tool_registry = {}
        for info in github_tools + osv_tools:
            self._tool_registry[info.tool.name] = info

        refreshed_iso = datetime.now(UTC).isoformat()
        self._github_status.tools = [i.tool for i in github_tools]
        self._github_status.last_refreshed_at = refreshed_iso
        self._osv_status.tools = [i.tool for i in osv_tools]
        self._osv_status.last_refreshed_at = refreshed_iso
        self._last_refreshed_at = refreshed_iso

        return self._tool_registry

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Execute a single MCP tool call and return parsed JSON result with metadata."""
        info = self._tool_registry.get(tool_name)
        if info is None:
            await self.refresh_tools()
            info = self._tool_registry.get(tool_name)
            if info is None:
                return {
                    "success": False,
                    "server_name": "unknown",
                    "tool_name": tool_name,
                    "error": f"Tool '{tool_name}' is not available in either MCP server. Available tools: {list(self._tool_registry.keys())}",
                }

        server_name = info.server_name
        if server_name == "github-service-mcp":
            script_path = str(
                PROJECT_ROOT / "github_service" / "synapse_auto_server.py"
            )
        else:
            script_path = str(PROJECT_ROOT / "osv_service" / "synapse_auto_server.py")

        params = self._server_params(server_name, script_path)
        start_ns = time.monotonic_ns()

        try:
            async with asyncio.timeout(timeout):
                async with stdio_client(params) as (read_stream, write_stream):  # noqa: SIM117
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        result = await session.call_tool(tool_name, arguments)

            duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000

            raw_text = ""
            if result.content:
                texts = [
                    block.text
                    for block in result.content
                    if hasattr(block, "text") and block.text
                ]
                raw_text = "\n".join(texts)

            parsed: Any = raw_text
            try:
                parsed = json.loads(raw_text)
            except (json.JSONDecodeError, TypeError):
                parsed = {"raw": raw_text}

            is_err = bool(getattr(result, "is_error", False)) or (
                isinstance(parsed, dict) and "error" in parsed
            )
            err_msg = (
                parsed.get("error") if isinstance(parsed, dict) and is_err else None
            )

            return {
                "success": not is_err,
                "server_name": server_name,
                "tool_name": tool_name,
                "result": parsed,
                "error": err_msg,
                "duration_ms": round(duration_ms, 2),
                "is_error": is_err,
            }

        except TimeoutError:
            duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000
            return {
                "success": False,
                "server_name": server_name,
                "tool_name": tool_name,
                "error": f"Tool call timed out after {timeout}s",
                "duration_ms": round(duration_ms, 2),
            }
        except Exception as exc:  # noqa: BLE001
            duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000
            return {
                "success": False,
                "server_name": server_name,
                "tool_name": tool_name,
                "error": f"{type(exc).__name__}: {exc}",
                "duration_ms": round(duration_ms, 2),
            }


_client_manager: MCPClientManager | None = None


def get_mcp_client() -> MCPClientManager:
    global _client_manager
    if _client_manager is None:
        _client_manager = MCPClientManager()
    return _client_manager
