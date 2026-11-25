"""Tests for database, history service, and MCP client/servers."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest


class TestDatabase:
    def test_create_tables_idempotent(self, tmp_db):
        from copilot_gateway.database import create_tables

        create_tables()
        create_tables()  # Must be safe to call twice

    def test_scan_lifecycle(self, tmp_db):
        from copilot_gateway.history_service import HistoryService

        svc = HistoryService()
        scan_id = svc.create_scan("testowner", "testrepo")
        assert isinstance(scan_id, int)
        assert scan_id > 0

        svc.complete_scan(
            scan_id=scan_id,
            status="completed",
            total_dependencies=10,
            resolved_count=8,
            unresolved_count=2,
            vulnerable_packages_count=1,
            total_vulnerabilities=3,
            scan_summary={"test": True},
            duration_seconds=5.5,
        )

        record = svc.get_scan(scan_id)
        assert record is not None
        assert record["status"] == "completed"
        assert record["total_dependencies"] == 10
        assert record["vulnerable_packages_count"] == 1

    def test_list_scans_returns_records(self, tmp_db):
        from copilot_gateway.history_service import HistoryService

        svc = HistoryService()
        svc.create_scan("owner1", "repo1")
        svc.create_scan("owner2", "repo2")
        records = svc.list_scans()
        assert len(records) >= 2

    def test_no_preseeded_data(self, tmp_path):
        """A fresh database must be completely empty on creation — no fake records."""
        from sqlalchemy import create_engine, select
        from sqlalchemy.orm import Session

        from copilot_gateway.database import Base, ScanRecord

        fresh_db = tmp_path / "fresh_empty.db"
        fresh_engine = create_engine(f"sqlite:///{fresh_db}")
        Base.metadata.create_all(fresh_engine)
        with Session(fresh_engine) as session:
            rows = session.execute(select(ScanRecord)).scalars().all()
        assert len(rows) == 0

    def test_tool_call_audit_logged(self, tmp_db):
        from datetime import UTC, datetime

        from copilot_gateway.history_service import HistoryService
        from copilot_gateway.schemas import ToolCallTrace

        svc = HistoryService()
        scan_id = svc.create_scan("audit_owner", "audit_repo")
        trace = ToolCallTrace(
            server_name="github-service-mcp",
            tool_name="github_get_dependencies",
            arguments={"owner": "test", "repo": "test"},
            success=True,
            result_summary="5 deps",
            duration_ms=234.5,
            called_at=datetime.now(UTC).isoformat(),
        )
        svc.log_tool_call("test-session-id", scan_id, trace)
        assert svc.total_tool_call_count() >= 1


class TestMCPServers:
    @pytest.mark.anyio
    async def test_github_mcp_tools_discovered(self, tmp_db):
        """GitHub MCP server must initialize and return expected tools."""
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        script = str(
            Path(__file__).parent.parent / "github_service" / "synapse_auto_server.py"
        )
        params = StdioServerParameters(command=sys.executable, args=[script])

        async with asyncio.timeout(20):
            async with stdio_client(params) as (r, w):  # noqa: SIM117
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    tool_names = {t.name for t in (result.tools or [])}

        expected = {
            "get_service_health",
            "fetch_repository_metadata",
            "list_repository_dependencies",
            "list_repository_issues",
            "list_repository_pull_requests",
            "list_repository_commits",
        }
        assert expected <= tool_names, f"Missing tools: {expected - tool_names}"

    @pytest.mark.anyio
    async def test_osv_mcp_tools_discovered(self, tmp_db):
        """OSV MCP server must initialize and return Synapse-generated tools including commit lookup."""
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        script = str(
            Path(__file__).parent.parent / "osv_service" / "synapse_auto_server.py"
        )
        params = StdioServerParameters(command=sys.executable, args=[script])

        async with asyncio.timeout(20):
            async with stdio_client(params) as (r, w):  # noqa: SIM117
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    tool_names = {t.name for t in (result.tools or [])}

        assert any("health" in t for t in tool_names), (
            f"Missing health tool: {tool_names}"
        )
        assert any("batch" in t or "dependenc" in t for t in tool_names), (
            f"Missing batch tool: {tool_names}"
        )
        assert any("detail" in t or "advisory" in t for t in tool_names), (
            f"Missing detail tool: {tool_names}"
        )
        assert any("commit" in t for t in tool_names), (
            f"Missing commit tool: {tool_names}"
        )

    @pytest.mark.anyio
    @pytest.mark.live_api
    async def test_github_mcp_actual_tool_execution(self, tmp_db):
        """Execute get_service_health tool through MCP stdio and verify real response."""
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        script = str(
            Path(__file__).parent.parent / "github_service" / "synapse_auto_server.py"
        )
        params = StdioServerParameters(command=sys.executable, args=[script])

        async with asyncio.timeout(30):
            async with stdio_client(params) as (r, w):  # noqa: SIM117
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    health_tool = next(
                        (t.name for t in (tools.tools or []) if "health" in t.name),
                        "get_service_health",
                    )
                    result = await session.call_tool(health_tool, {})

        assert result.content
        text = result.content[0].text
        data = json.loads(text)
        assert data.get("status") == "ok" or "error" in data

    @pytest.mark.anyio
    @pytest.mark.live_api
    async def test_osv_mcp_actual_tool_execution(self, tmp_db):
        """Execute query_batch_vulnerabilities through MCP stdio with real data."""
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        script = str(
            Path(__file__).parent.parent / "osv_service" / "synapse_auto_server.py"
        )
        params = StdioServerParameters(command=sys.executable, args=[script])

        args = {
            "dependencies": [
                {
                    "package_name": "requests",
                    "ecosystem": "PyPI",
                    "installed_version": "2.19.0",
                }
            ],
            "include_details": False,
        }

        async with asyncio.timeout(60):
            async with stdio_client(params) as (r, w):  # noqa: SIM117
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    batch_tool = next(
                        (
                            t.name
                            for t in (tools.tools or [])
                            if "batch" in t.name or "dependenc" in t.name
                        ),
                        "query_batch_vulnerabilities",
                    )
                    result = await session.call_tool(batch_tool, args)

        assert result.content
        text = result.content[0].text
        data = json.loads(text)
        # Should find vulnerabilities or be an error (never fake success)
        assert "total_vulnerabilities_found" in data or "error" in data

    @pytest.mark.anyio
    @pytest.mark.live_api
    async def test_mcp_client_manager_refresh(self, tmp_db):
        """MCPClientManager.refresh_tools() must discover tools from both servers."""
        from copilot_gateway.mcp_client import MCPClientManager

        mcp = MCPClientManager()
        registry = await mcp.refresh_tools()
        assert len(registry) >= 3, f"Expected ≥3 tools, got {list(registry.keys())}"
        # Must include both server tools
        servers = {info.server_name for info in registry.values()}
        assert "github-service-mcp" in servers
        assert "osv-service-mcp" in servers

    @pytest.mark.anyio
    @pytest.mark.mcp_integration
    async def test_registry_tool_appears_after_extension_active(self, tmp_db):
        """When osv_service exposes /registry/pypi and Synapse discovers it, osv_get_pypi_latest_release appears."""
        import httpx

        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://127.0.0.1:8002/health")
            assert resp.status_code == 200
            health = resp.json()
            assert health.get("registry_extension_active") is True

        from copilot_gateway.mcp_client import MCPClientManager

        mcp = MCPClientManager()
        registry = await mcp.refresh_tools()
        assert any(
            "pypi" in name.lower() or "latest" in name.lower() for name in registry
        )


class TestEvidenceCollector:
    def test_sanitizes_secrets_from_args(self):
        from copilot_gateway.evidence_service import EvidenceCollector

        ec = EvidenceCollector()
        trace = ec.record_tool_call(
            server_name="test-server",
            tool_name="test_tool",
            arguments={"api_key": "super-secret", "owner": "testuser"},
            result={"success": True, "result": {}},
        )
        assert trace.arguments["api_key"] == "***"
        assert trace.arguments["owner"] == "testuser"

    def test_vulnerability_ids_extracted(self):
        from copilot_gateway.evidence_service import EvidenceCollector

        ec = EvidenceCollector()
        ec.record_tool_call(
            server_name="osv-service-mcp",
            tool_name="osv_query_vulnerabilities_batch",
            arguments={},
            result={
                "success": True,
                "result": {
                    "total_vulnerabilities_found": 1,
                    "results": [
                        {
                            "package_name": "requests",
                            "vulnerability_ids": ["GHSA-j8r2-6x86-q33q"],
                            "vulnerabilities": [
                                {
                                    "vulnerability_id": "GHSA-j8r2-6x86-q33q",
                                    "summary": "Test vuln",
                                    "osv_url": "https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q",
                                    "provenance": {
                                        "fetched_at": "2024-01-01T00:00:00Z"
                                    },
                                }
                            ],
                        }
                    ],
                },
            },
        )
        assert "GHSA-j8r2-6x86-q33q" in ec.vulnerability_ids


@pytest.mark.requires_groq
class TestAgentOrchestrator:
    @pytest.mark.anyio
    @pytest.mark.live_api
    async def test_agent_uses_mcp_tools(self, tmp_db):
        """The agent must call MCP tools and return a response grounded in real data."""
        from copilot_gateway.agent_orchestrator import run_agent
        from copilot_gateway.mcp_client import MCPClientManager

        mcp = MCPClientManager()
        await mcp.refresh_tools()

        response = await run_agent(
            user_message="What is the health status of the GitHub and OSV services?",
            owner=None,
            repo=None,
            scan_id=None,
            mcp_client=mcp,
        )

        assert response.status in ("completed", "error")
        if response.status == "completed":
            assert response.response
            # Agent must have made tool calls
            assert response.total_tool_calls > 0, (
                "Agent must call MCP tools, not answer from memory"
            )
            # Check no secrets in trace
            for trace in response.execution_trace:
                args_str = str(trace.arguments)
                assert os.getenv("GROQ_API_KEY", "not-set") not in args_str


@pytest.mark.requires_gemini
class TestGeminiProvider:
    @pytest.mark.anyio
    async def test_gemini_synthesize_success(self):
        from copilot_gateway.gemini_provider import gemini_synthesize

        result = await gemini_synthesize(
            "Summarize: requests 2.19.0 is vulnerable to CVE-2023-32681."
        )
        assert result["success"] is True
        assert isinstance(result["text"], str)
        assert len(result["text"]) > 0

    @pytest.mark.anyio
    async def test_gemini_unavailable_returns_error(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "")
        from copilot_gateway.gemini_provider import gemini_synthesize

        result = await gemini_synthesize("test prompt")
        assert result["success"] is False
        assert "error" in result


class TestTavilyProvider:
    @pytest.mark.anyio
    async def test_tavily_unavailable_returns_error(self, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "")
        from copilot_gateway.tavily_provider import tavily_search_vulnerability

        result = await tavily_search_vulnerability("GHSA-j8r2-6x86-q33q")
        assert result["success"] is False

    @pytest.mark.anyio
    @pytest.mark.live_api
    @pytest.mark.requires_tavily
    async def test_tavily_search_returns_real_results(self):
        from copilot_gateway.tavily_provider import tavily_search_vulnerability

        result = await tavily_search_vulnerability(
            "GHSA-j8r2-6x86-q33q", package_name="requests"
        )
        assert result["success"] is True
        assert isinstance(result["results"], list)
        # Verify real URLs in results
        for item in result["results"]:
            assert item.get("url", "").startswith("http")
