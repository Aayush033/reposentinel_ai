"""Tests for OSV commit-hash lookup, pagination, caching, agent workflow, and UI integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.types import Tool
from pydantic import ValidationError

from copilot_gateway.agent_orchestrator import run_commit_check
from copilot_gateway.main import app as gateway_app
from copilot_gateway.mcp_client import MCPClientManager, MCPToolInfo
from osv_service.config import OSVServiceSettings
from osv_service.main import app as osv_app
from osv_service.osv_client import OSVAPIError, OSVClient
from osv_service.schemas import CommitVulnerabilityRequest

TEST_COMMIT_SHA = "6879efc2c1596d11a6a6ad296f80063b558d5e0f"


class TestCommitHashValidation:
    @pytest.mark.parametrize(
        "bad_commit",
        [
            "",
            "main",
            "HEAD",
            "abc1234",
            "6879efc2c1596d11a6a6ad296f80063b558d5e0",  # 39 chars
            "zzzzefc2c1596d11a6a6ad296f80063b558d5e0f",  # non-hex
            "fix security bug",
        ],
    )
    def test_invalid_commit_rejected(self, bad_commit):
        with pytest.raises(ValidationError):
            CommitVulnerabilityRequest(commit=bad_commit)
        with pytest.raises(OSVAPIError) as exc_info:
            OSVClient.validate_commit_hash(bad_commit)
        assert exc_info.value.status_code == 422

    def test_valid_sha1_and_sha256_accepted(self):
        req = CommitVulnerabilityRequest(commit=f"  {TEST_COMMIT_SHA.upper()}  ")
        assert req.commit == TEST_COMMIT_SHA
        sha256 = "a" * 64
        req2 = CommitVulnerabilityRequest(commit=sha256)
        assert req2.commit == sha256


class TestOSVCommitClientBehavior:
    @pytest.mark.anyio
    async def test_payload_pagination_and_cache(self, tmp_path, monkeypatch):
        db_path = tmp_path / "commit_cache.db"
        settings = OSVServiceSettings(cache_db_path=db_path, cache_ttl_seconds=300)
        client = OSVClient(settings)

        sent_bodies: list[dict] = []
        call_count = 0

        async def fake_post(self, url, json=None, **kwargs):
            nonlocal call_count
            call_count += 1
            sent_bodies.append(json)
            req = httpx.Request("POST", url)
            if call_count == 1:
                return httpx.Response(
                    200,
                    json={
                        "vulns": [{"id": "OSV-TEST-1", "summary": "Page 1 vuln"}],
                        "next_page_token": "tok-2",
                    },
                    request=req,
                )
            return httpx.Response(
                200,
                json={"vulns": [{"id": "OSV-TEST-2", "summary": "Page 2 vuln"}]},
                request=req,
            )

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        res1 = await client.query_commit(TEST_COMMIT_SHA)
        assert res1.commit_hash == TEST_COMMIT_SHA
        assert res1.vulnerability_count == 2
        assert [v.vulnerability_id for v in res1.vulnerabilities] == [
            "OSV-TEST-1",
            "OSV-TEST-2",
        ]
        assert res1.cached is False
        # Confirm NO 'version' field was sent
        assert sent_bodies[0] == {"commit": TEST_COMMIT_SHA}
        assert sent_bodies[1] == {"commit": TEST_COMMIT_SHA, "page_token": "tok-2"}

        # Second call should hit SQLite cache
        res2 = await client.query_commit(TEST_COMMIT_SHA)
        assert res2.cached is True
        assert res2.vulnerability_count == 2
        assert call_count == 2

    @pytest.mark.anyio
    async def test_infinite_pagination_loop_guarded(self, tmp_path, monkeypatch):
        settings = OSVServiceSettings(
            cache_db_path=tmp_path / "loop.db", cache_ttl_seconds=0
        )
        client = OSVClient(settings)
        calls = 0

        async def fake_post(self, url, json=None, **kwargs):
            nonlocal calls
            calls += 1
            req = httpx.Request("POST", url)
            return httpx.Response(
                200,
                json={"vulns": [], "next_page_token": "same-token"},
                request=req,
            )

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        res = await client.query_commit(TEST_COMMIT_SHA)
        assert res.vulnerability_count == 0
        assert calls == 2  # initial + 1 repeat detected -> breaks cleanly

    @pytest.mark.anyio
    async def test_empty_response_returns_zero_vulns(self, tmp_path, monkeypatch):
        settings = OSVServiceSettings(
            cache_db_path=tmp_path / "empty.db", cache_ttl_seconds=0
        )
        client = OSVClient(settings)

        async def fake_post(self, url, json=None, **kwargs):
            return httpx.Response(200, json={}, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        res = await client.query_commit(TEST_COMMIT_SHA)
        assert res.vulnerability_count == 0
        assert res.vulnerabilities == []

    @pytest.mark.anyio
    async def test_network_failure_raises_error_never_clean_scan(
        self, tmp_path, monkeypatch
    ):
        settings = OSVServiceSettings(
            cache_db_path=tmp_path / "err.db", cache_ttl_seconds=0
        )
        client = OSVClient(settings)

        async def fake_post_err(self, url, json=None, **kwargs):
            raise httpx.ConnectError("connection refused")

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post_err)
        with pytest.raises(OSVAPIError) as exc_info:
            await client.query_commit(TEST_COMMIT_SHA)
        assert exc_info.value.status_code == 502


class TestOSVCommitFastAPIEndpoint:
    @pytest.mark.anyio
    async def test_invalid_commit_returns_422(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/vulnerabilities/query-commit", json={"commit": "main"}
            )
        assert resp.status_code == 422

    @pytest.mark.anyio
    @pytest.mark.live_api
    async def test_real_osv_commit_example(self, tmp_db):
        """Run the documented real OSV commit SHA against https://api.osv.dev/v1/query."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/vulnerabilities/query-commit", json={"commit": TEST_COMMIT_SHA}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["commit_hash"] == TEST_COMMIT_SHA
        assert data["vulnerability_count"] >= 1
        assert data["source_url"] == "https://api.osv.dev/v1/query"


class TestAgentAndFrontendCommitIntegration:
    @pytest.mark.anyio
    async def test_run_commit_check_fetches_latest_sha_and_queries_osv(self, tmp_db):
        mcp = MCPClientManager()
        mcp._tool_registry = {
            "list_repository_commits": MCPToolInfo(
                server_name="github-service-mcp",
                tool=Tool(
                    name="list_repository_commits",
                    description="List commits",
                    input_schema={"type": "object", "properties": {}},
                ),
            ),
            "query_vulnerabilities_by_commit_hash": MCPToolInfo(
                server_name="osv-service-mcp",
                tool=Tool(
                    name="query_vulnerabilities_by_commit_hash",
                    description="Query commit",
                    input_schema={"type": "object", "properties": {}},
                ),
            ),
        }

        calls: list[tuple[str, dict]] = []

        async def fake_call_tool(tool_name, arguments, timeout=60.0):
            calls.append((tool_name, arguments))
            if tool_name == "list_repository_commits":
                return {
                    "success": True,
                    "server_name": "github-service-mcp",
                    "tool_name": tool_name,
                    "duration_ms": 12.0,
                    "result": {
                        "commits": [
                            {
                                "sha": TEST_COMMIT_SHA,
                                "short_sha": TEST_COMMIT_SHA[:7],
                                "message": "Example commit",
                                "author_login": "octocat",
                                "html_url": f"https://github.com/octo/repo/commit/{TEST_COMMIT_SHA}",
                            }
                        ]
                    },
                }
            return {
                "success": True,
                "server_name": "osv-service-mcp",
                "tool_name": tool_name,
                "duration_ms": 18.0,
                "result": {
                    "commit_hash": TEST_COMMIT_SHA,
                    "vulnerability_count": 1,
                    "vulnerabilities": [{"vulnerability_id": "OSV-2020-484"}],
                    "source": "osv_api",
                    "source_url": "https://api.osv.dev/v1/query",
                    "fetched_at": "2026-11-25T00:00:00Z",
                    "http_status": 200,
                    "cached": False,
                    "data_freshness": "live",
                },
            }

        mcp.call_tool = AsyncMock(side_effect=fake_call_tool)
        res = await run_commit_check("octo", "repo", None, mcp_client=mcp)
        assert res["commit_hash"] == TEST_COMMIT_SHA
        assert res["vulnerability_count"] == 1
        assert calls[0][0] == "list_repository_commits"
        assert calls[1] == (
            "query_vulnerabilities_by_commit_hash",
            {"commit": TEST_COMMIT_SHA},
        )

    @pytest.mark.anyio
    async def test_frontend_commit_section_and_gateway_validation(self, tmp_db):
        html = Path("copilot_gateway/static/index.html").read_text(encoding="utf-8")
        assert "COMMIT SECURITY LOOKUP" in html.upper()
        assert "section-commit" in html
        assert "btn-check-commit" in html

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/commit-check", json={"commit": "not-a-valid-sha"}
            )
        assert resp.status_code == 422

    def test_powershell_scripts_parse_cleanly(self):
        for ps1 in Path("scripts").glob("*.ps1"):
            content = ps1.read_text(encoding="utf-8")
            assert "✓" not in content and "✗" not in content, (
                f"Non-ASCII checkmark in {ps1} breaks PS 5.1"
            )
        verify_txt = Path("scripts/verify_all.ps1").read_text(encoding="utf-8")
        assert "exit 1" in verify_txt
        act_txt = Path("scripts/activate_registry_demo.ps1").read_text(encoding="utf-8")
        assert "Get-CimInstance Win32_Process" in act_txt
