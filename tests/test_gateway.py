"""Tests for copilot_gateway business logic, cross-system correlation, AI fallbacks.

All tests call internal functions directly — no HTTP layer, no ASGI transport,
no event-loop or socket infrastructure needed (sandbox blocks socket.socketpair).

The 'run_agent' and async provider functions are exercised via asyncio.run()
with a fresh event loop on the main thread which does NOT use anyio's
blocking-portal (that's what starlette TestClient does and what blocks).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from copilot_gateway.agent_orchestrator import _correlate_github_records, run_agent
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
    def test_groq_missing_key_reports_failure(self, monkeypatch, tmp_db):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        from copilot_gateway.groq_provider import groq_chat_with_tools

        # Use a fresh loop directly on main thread — no anyio blocking portal
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(
                groq_chat_with_tools(messages=[{"role": "user", "content": "hi"}])
            )
        finally:
            loop.close()
        assert res["success"] is False
        assert "GROQ_API_KEY" in res["error"]

    def test_agent_falls_back_to_groq_when_gemini_unavailable(
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

        loop = asyncio.new_event_loop()
        try:
            resp = loop.run_until_complete(
                run_agent("Check status", None, None, None, mcp_client=mcp)
            )
        finally:
            loop.close()

        assert resp.status == "completed"
        assert resp.groq_model_used == "openai/gpt-oss-120b"
        assert resp.gemini_model_used is None
        assert "Groq verified report" in resp.response

    def test_gemini_fallback_on_provider_error(self, monkeypatch):
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
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(gemini_synthesize("Summarize findings"))
        finally:
            loop.close()
        assert result["success"] is True
        assert result["model"] == "gemini-3.5-flash-lite"
        assert called_models == ["gemini-3.8-flash", "gemini-3.5-flash-lite"]


class TestDemoRegistryExtension:
    def test_osv_initial_app_excludes_registry_route(self):
        """OSV app baseline must NOT include the PyPI registry route."""
        paths = {getattr(r, "path", "") for r in osv_app.routes}
        assert "/registry/pypi/{package_name}/latest-release" not in paths

    def test_pypi_router_registration(self):
        """When the PyPI router is included, the route appears in the app or router."""
        paths = [getattr(r, "path", "") for r in pypi_registry_router.routes]
        assert "/registry/pypi/{package_name}/latest-release" in paths
