"""Tests for github_service and osv_service FastAPI endpoints (async ASGI)."""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

from github_service.main import app as github_app
from osv_service.main import app as osv_app


class TestGitHubServiceHealth:
    @pytest.mark.anyio
    async def test_health_ok(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "github_service"
        assert isinstance(data["token_configured"], bool)
        assert isinstance(data["cached_entries"], int)

    @pytest.mark.anyio
    async def test_health_no_secrets_exposed(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        content = resp.text
        token = os.getenv("GITHUB_TOKEN", "")
        if token:
            assert token not in content


@pytest.mark.live_api
class TestGitHubServiceLiveAPI:
    @pytest.mark.anyio
    async def test_public_repo_metadata(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get("/repos/pallets/flask")
        assert resp.status_code == 200
        data = resp.json()
        assert data["full_name"] == "pallets/flask"
        assert data["owner"] == "pallets"
        assert data["repo"] == "flask"
        assert isinstance(data["stargazers_count"], int)
        assert "provenance" in data
        assert data["provenance"]["source"] == "github_rest_api"
        assert data["provenance"]["http_status"] == 200

    @pytest.mark.anyio
    async def test_dependencies_real_manifests(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get("/repos/pallets/flask/dependencies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_dependencies"] > 0
        assert isinstance(data["manifests_found"], list)
        assert len(data["manifests_found"]) > 0
        for dep in data["dependencies"]:
            assert "package_name" in dep
            assert "is_resolved" in dep
            assert "resolution_status" in dep
            if dep["is_resolved"]:
                assert dep["installed_version"] is not None
                assert dep["resolution_status"] == "pinned"
            else:
                assert dep["installed_version"] is None
                assert dep["resolution_status"] == "unresolved"

    @pytest.mark.anyio
    async def test_unresolved_version_never_fabricated(self, tmp_db):
        """Verify no unresolved dep has an invented installed_version."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get("/repos/pallets/flask/dependencies")
        assert resp.status_code == 200
        for dep in resp.json()["dependencies"]:
            if not dep["is_resolved"]:
                assert dep["installed_version"] is None, (
                    f"Unresolved dep {dep['package_name']} has fabricated installed_version={dep['installed_version']}"
                )

    @pytest.mark.anyio
    async def test_issues_paginated(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/repos/pallets/flask/issues", params={"state": "open", "per_page": 5}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["issues"], list)
        assert data["count"] <= 5
        for issue in data["issues"]:
            assert "id" in issue
            assert issue["html_url"].startswith("https://github.com")

    @pytest.mark.anyio
    async def test_pulls_paginated(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/repos/pallets/flask/pulls", params={"state": "open", "per_page": 5}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["pull_requests"], list)

    @pytest.mark.anyio
    async def test_commits_paginated(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/repos/pallets/flask/commits", params={"per_page": 5}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["commits"], list)
        for commit in data["commits"]:
            assert len(commit["sha"]) == 40

    @pytest.mark.anyio
    async def test_404_for_nonexistent_repo(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=github_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/repos/nonexistent-owner-xyz-123/nonexistent-repo-xyz-456"
            )
        assert resp.status_code == 404


class TestOSVServiceHealth:
    @pytest.mark.anyio
    async def test_health_ok(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "osv_service"

    @pytest.mark.anyio
    async def test_empty_batch_returns_empty(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/vulnerabilities/query-batch", json={"dependencies": []}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_submitted"] == 0
        assert data["results"] == []

    @pytest.mark.anyio
    async def test_unresolved_dep_skipped_not_classified(self, tmp_db):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/vulnerabilities/query-batch",
                json={
                    "dependencies": [
                        {
                            "package_name": "flask",
                            "ecosystem": "PyPI",
                            "installed_version": None,
                        }
                    ]
                },
            )
        await asyncio.sleep(0.05)
        assert resp.status_code == 200
        data = resp.json()
        assert data["queried_count"] == 0
        assert data["unresolved_skipped_count"] == 1
        result = data["results"][0]
        assert result["status"] == "unresolved_skipped"
        assert result["vulnerability_ids"] == []

    @pytest.mark.anyio
    async def test_pypi_registry_not_in_initial_service(self, tmp_db):
        """The /registry/pypi endpoint must not be present in the initial service."""
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        ) as client:
            resp = await client.get("/registry/pypi/requests/latest-release")
        assert resp.status_code == 404, (
            "PyPI registry endpoint must not be active in the initial OSV service"
        )


@pytest.mark.live_api
class TestOSVServiceLiveAPI:
    @pytest.mark.anyio
    async def test_vulnerable_package_detected(self, tmp_db):
        """requests 2.19.0 is known vulnerable — OSV must return at least one finding."""
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        )
        try:
            resp = await client.post(
                "/vulnerabilities/query-batch",
                json={
                    "dependencies": [
                        {
                            "package_name": "requests",
                            "ecosystem": "PyPI",
                            "installed_version": "2.19.0",
                        }
                    ]
                },
            )
        finally:
            try:
                await client.aclose()
            except RuntimeError:
                pass
            await asyncio.sleep(0.1)

        assert resp.status_code == 200
        data = resp.json()
        assert data["total_vulnerabilities_found"] > 0, (
            "OSV should find vulnerabilities in requests 2.19.0"
        )
        result = data["results"][0]
        assert result["status"] == "vulnerable"
        assert len(result["vulnerability_ids"]) > 0
        for vuln in result.get("vulnerabilities", []):
            assert isinstance(vuln["fixed_versions"], list)

    @pytest.mark.anyio
    async def test_vulnerability_detail_real_data(self, tmp_db):
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=osv_app), base_url="http://test"
        )
        try:
            resp = await client.get("/vulnerabilities/GHSA-j8r2-6x86-q33q")
        finally:
            try:
                await client.aclose()
            except RuntimeError:
                pass
            await asyncio.sleep(0.1)

        assert resp.status_code == 200
        data = resp.json()
        assert data["vulnerability_id"] == "GHSA-j8r2-6x86-q33q"
        assert data["osv_url"].startswith("https://osv.dev/vulnerability/")
        assert "provenance" in data
        assert isinstance(data["fixed_versions"], list)
        assert isinstance(data["affected_ranges"], list)
