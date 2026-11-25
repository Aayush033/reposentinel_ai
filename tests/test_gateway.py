"""Tests for copilot_gateway API endpoints, cross-system correlation, AI fallbacks, and live registry extension."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from copilot_gateway.agent_orchestrator import _correlate_github_records, run_agent
from copilot_gateway.main import app as gateway_app
from copilot_gateway.mcp_client import MCPClientManager
from demo_extensions.pypi_registry_router import router as pypi_registry_router
from osv_service.main import app as osv_app


class TestCrossSystemCorrelation:
    def test_confirmed_vs_possible_match(self):
        vuln_rows = [
            {"package": "requests", "id": "GHSA-j8r2-6x86-q33q"},
            {"package": "urllib3", "id": "CVE-2023-45803"},
        ]
        items = [
            {
                "number": 101,
                "title": "Security: fix GHSA-j8r2-6x86-q33q in requests",
                "body": "Upgrades requests to 2.31.0",
                "state": "open",
            },
            {
                "number": 102,
                "title": "Bump urllib3 version in CI",
                "body": "Routine dependency update",
                "state": "open",
            },
            {
                "number": 103,
                "title": "Fix typo in README",
                "body": "Docs update",
                "state": "open",
            },
        ]
        correlated = _correlate_github_records(items, vuln_rows, "pr")
        by_num = {item["number"]: item for item in correlated}
        assert by_num[101]["correlation_status"] == "confirmed_match"
        assert "GHSA-j8r2-6x86-q33q" in by_num[101]["matched_vulnerability_ids"]
        assert by_num[102]["correlation_status"] == "possible_match"
        assert "urllib3" in by_num[102]["matched_packages"]
        assert by_num[103]["correlation_status"] == "uncorrelated"


class TestAIProviderFailuresAndFallbacks:
    @pytest.mark.anyio
    async def test_groq_missing_key_reports_failure(self, monkeypatch, tmp_db):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        from copilot_gateway.groq_provider import groq_chat_with_tools

        res = await groq_chat_with_tools(messages=[{"role": "user", "content": "hi"}])
        assert res["success"] is False
        assert "GROQ_API_KEY" in res["error"]

    @pytest.mark.anyio
    async def test_agent_falls_back_to_groq_when_gemini_unavailable(
        self, monkeypatch, tmp_db
    ):
        monkeypatch.setenv("GROQ_API_KEY", "test-groq-key")
        monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")

        fake_msg = SimpleNamespace(
            content="Groq verified report from MCP tools.", tool_calls=[]
        )

        async def fake_groq_chat(**kwargs):
            return {
                "success": True,
                "model": "openai/gpt-oss-120b",
                "message": fake_msg,
                "finish_reason": "stop",
            }

        async def fake_gemini_fail(**kwargs):
            return {
                "success": False,
                "error": "503 Service Unavailable",
                "model": "gemini-3.8-flash",
            }

        monkeypatch.setattr(
            "copilot_gateway.agent_orchestrator.groq_chat_with_tools", fake_groq_chat
        )
        monkeypatch.setattr(
            "copilot_gateway.agent_orchestrator.gemini_synthesize", fake_gemini_fail
        )

        mcp = MCPClientManager()
        # Provide one already-discovered tool in registry to avoid stdio spawn for this unit test
        from mcp.types import Tool

        from copilot_gateway.mcp_client import MCPToolInfo

        mcp._tool_registry = {
            "osv_health": MCPToolInfo(
                server_name="osv-service-mcp",
                tool=Tool(
                    name="osv_health",
                    description="Health",
                    input_schema={"type": "object", "properties": {}},
                ),
            )
        }

        resp = await run_agent("Check status", None, None, None, mcp_client=mcp)
        assert resp.status == "completed"
        assert resp.groq_model_used == "openai/gpt-oss-120b"
        assert resp.gemini_model_used is None
        assert "Groq verified report" in resp.response

    @pytest.mark.anyio
    async def test_gemini_fallback_on_provider_error(self, monkeypatch):
        from copilot_gateway.gemini_provider import gemini_synthesize

        monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
        monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
        monkeypatch.setenv("GEMINI_FALLBACK_MODEL", "gemini-3.5-flash-lite")

        called_models: list[str] = []

        class FakeModels:
            def generate_content(self, model, contents, config):
                called_models.append(model)
                if model == "gemini-3.8-flash":
                    raise RuntimeError("404 model not found")
                return SimpleNamespace(text="Synthesized by fallback model")

        class FakeClient:
            def __init__(self, api_key):
                self.models = FakeModels()

        monkeypatch.setattr("google.genai.Client", FakeClient)
        result = await gemini_synthesize("Summarize findings")
        assert result["success"] is True
        assert result["model"] == "gemini-3.5-flash-lite"
        assert called_models == ["gemini-3.8-flash", "gemini-3.5-flash-lite"]


class TestGatewayAPI:
    @pytest.mark.anyio
    async def test_gateway_health_and_live_state_and_empty_history(self, tmp_db):
        from copilot_gateway.database import create_tables

        create_tables()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app), base_url="http://test"
        ) as client:
            health = await client.get("/health")
            assert health.status_code == 200
            hdata = health.json()
            assert hdata["service"] == "copilot_gateway"
            assert hdata["status"] == "ok"

            state = await client.get("/api/live-state")
            assert state.status_code == 200
            sdata = state.json()
            assert "services" in sdata
            assert set(sdata["services"].keys()) == {
                "github-service",
                "osv-service",
                "github-mcp",
                "osv-mcp",
                "groq",
                "gemini",
            }

            hist = await client.get("/api/history")
            assert hist.status_code == 200
            assert isinstance(hist.json(), list)

            tools = await client.get("/api/mcp-tools")
            assert tools.status_code == 200
            assert "tools" in tools.json()

            index_resp = await client.get("/static/index.html")
            assert index_resp.status_code == 200
            assert "RepoSentinel" in index_resp.text

    @pytest.mark.anyio
    async def test_chat_without_groq_key_returns_503(self, monkeypatch, tmp_db):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/chat", json={"message": "hello"})
        assert resp.status_code == 503


class TestDemoRegistryExtension:
    def test_osv_initial_app_excludes_registry_route(self):
        paths = {getattr(r, "path", "") for r in osv_app.routes}
        assert "/registry/pypi/{package_name}/latest-release" not in paths

    @pytest.mark.anyio
    @pytest.mark.live_api
    async def test_live_pypi_extension_router(self):
        demo_app = FastAPI()
        demo_app.include_router(pypi_registry_router)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=demo_app), base_url="http://test"
        ) as client:
            ok_resp = await client.get("/registry/pypi/requests/latest-release")
            assert ok_resp.status_code == 200
            data = ok_resp.json()
            assert data["package_name"].lower() == "requests"
            assert data["latest_version"]
            assert data["source_url"] == "https://pypi.org/pypi/requests/json"
            assert data["fetched_at"]

            missing_resp = await client.get(
                "/registry/pypi/definitely-nonexistent-pkg-999999/latest-release"
            )
            assert missing_resp.status_code == 404
