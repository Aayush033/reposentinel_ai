"""Real GitHub REST API client with SQLite response caching and rate-limit tracking."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import GitHubServiceSettings


class GitHubAPIError(Exception):
    """Raised when GitHub REST API returns an error or cannot be reached."""

    def __init__(self, status_code: int, message: str, source_url: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.source_url = source_url


class GitHubClient:
    """Async client for https://api.github.com backed by an explicit SQLite cache."""

    def __init__(self, settings: GitHubServiceSettings) -> None:
        self.settings = settings
        self.last_rate_limit_remaining: int | None = None
        self.last_rate_limit_reset: str | None = None
        self._init_cache_db()

    def _init_cache_db(self) -> None:
        self.settings.cache_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.settings.cache_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_cache (
                    cache_key TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    http_status INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    cache_created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def count_cached_entries(self) -> int:
        with sqlite3.connect(self.settings.cache_db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM api_cache").fetchone()
            return int(row[0]) if row else 0

    def _build_headers(
        self, accept: str = "application/vnd.github+json"
    ) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "User-Agent": "RepoSentinel-AI-GitHubService/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        return headers

    def _get_cached(self, cache_key: str) -> dict[str, Any] | None:
        now_iso = datetime.now(UTC).isoformat()
        with sqlite3.connect(self.settings.cache_db_path) as conn:
            row = conn.execute(
                """
                SELECT source, source_url, http_status, payload_json, fetched_at, cache_created_at, expires_at
                FROM api_cache
                WHERE cache_key = ? AND expires_at > ?
                """,
                (cache_key, now_iso),
            ).fetchone()
        if not row:
            return None
        return {
            "source": row[0],
            "source_url": row[1],
            "http_status": int(row[2]),
            "payload": json.loads(row[3]),
            "fetched_at": row[4],
            "cache_created_at": row[5],
            "expires_at": row[6],
            "cached": True,
            "data_freshness": f"cached (expires_at={row[6]})",
        }

    def _store_cache(
        self,
        cache_key: str,
        source_url: str,
        http_status: int,
        payload: Any,
        fetched_at: str,
    ) -> str:
        created_at = datetime.now(UTC)
        expires_at = created_at + timedelta(seconds=self.settings.cache_ttl_seconds)
        with sqlite3.connect(self.settings.cache_db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO api_cache
                (cache_key, source, source_url, http_status, payload_json, fetched_at, cache_created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    "github_rest_api",
                    source_url,
                    http_status,
                    json.dumps(payload),
                    fetched_at,
                    created_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            conn.commit()
        return created_at.isoformat()

    def _update_rate_limit(self, headers: httpx.Headers) -> None:
        rem = headers.get("X-RateLimit-Remaining")
        rst = headers.get("X-RateLimit-Reset")
        if rem is not None and rem.isdigit():
            self.last_rate_limit_remaining = int(rem)
        if rst is not None and rst.isdigit():
            self.last_rate_limit_reset = datetime.fromtimestamp(
                int(rst), tz=UTC
            ).isoformat()

    async def get_json(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """Perform an authenticated or public GET request against GitHub REST API."""
        url = f"{self.settings.github_api_base}{path}"
        sorted_params = sorted((params or {}).items())
        cache_key = f"GET:{url}:{json.dumps(sorted_params)}"

        if use_cache and self.settings.cache_ttl_seconds > 0:
            cached = self._get_cached(cache_key)
            if cached is not None:
                return cached

        try:
            async with httpx.AsyncClient(
                timeout=self.settings.request_timeout_seconds
            ) as client:
                response = await client.get(
                    url, params=params, headers=self._build_headers()
                )
        except httpx.TimeoutException as exc:
            raise GitHubAPIError(
                status_code=504,
                message=f"GitHub API request timed out after {self.settings.request_timeout_seconds}s: {exc}",
                source_url=str(url),
            ) from exc
        except httpx.HTTPError as exc:
            raise GitHubAPIError(
                status_code=502,
                message=f"Network error contacting GitHub API: {exc}",
                source_url=str(url),
            ) from exc

        self._update_rate_limit(response.headers)
        actual_url = str(response.url)
        fetched_at = datetime.now(UTC).isoformat()

        if response.status_code == 401:
            raise GitHubAPIError(
                status_code=401,
                message="GitHub API authentication failed (401). Check GITHUB_TOKEN permissions.",
                source_url=actual_url,
            )
        if response.status_code == 403:
            rem = response.headers.get("X-RateLimit-Remaining")
            if rem == "0":
                reset_info = self.last_rate_limit_reset or "unknown"
                raise GitHubAPIError(
                    status_code=429,
                    message=f"GitHub API rate limit exceeded. Resets at {reset_info}. Configure GITHUB_TOKEN for higher limits.",
                    source_url=actual_url,
                )
            raise GitHubAPIError(
                status_code=403,
                message="GitHub API access forbidden (403). Private repositories require a valid read-scoped GITHUB_TOKEN.",
                source_url=actual_url,
            )
        if response.status_code == 404:
            raise GitHubAPIError(
                status_code=404,
                message="GitHub resource not found (404). Verify owner/repo or token read permissions for private repositories.",
                source_url=actual_url,
            )
        if response.status_code >= 400:
            detail = response.text[:300]
            raise GitHubAPIError(
                status_code=response.status_code,
                message=f"GitHub API returned HTTP {response.status_code}: {detail}",
                source_url=actual_url,
            )

        payload = response.json()
        cache_created_at = (
            self._store_cache(
                cache_key, actual_url, response.status_code, payload, fetched_at
            )
            if self.settings.cache_ttl_seconds > 0
            else fetched_at
        )
        return {
            "source": "github_rest_api",
            "source_url": actual_url,
            "http_status": response.status_code,
            "payload": payload,
            "fetched_at": fetched_at,
            "cache_created_at": cache_created_at,
            "cached": False,
            "data_freshness": "live",
        }

    async def get_raw_file(
        self,
        owner: str,
        repo: str,
        file_path: str,
        ref: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch raw file content via GitHub Contents API, returning None if file does not exist (404)."""
        params = {"ref": ref} if ref else None
        url = (
            f"{self.settings.github_api_base}/repos/{owner}/{repo}/contents/{file_path}"
        )
        cache_key = f"RAW:{url}:ref={ref or ''}"

        if self.settings.cache_ttl_seconds > 0:
            cached = self._get_cached(cache_key)
            if cached is not None:
                return cached

        headers = self._build_headers(accept="application/vnd.github.raw+json")
        try:
            async with httpx.AsyncClient(
                timeout=self.settings.request_timeout_seconds
            ) as client:
                response = await client.get(url, params=params, headers=headers)
        except httpx.TimeoutException as exc:
            raise GitHubAPIError(
                status_code=504,
                message=f"GitHub Contents API timed out for {file_path}: {exc}",
                source_url=url,
            ) from exc
        except httpx.HTTPError as exc:
            raise GitHubAPIError(
                status_code=502,
                message=f"Network error fetching {file_path} from GitHub: {exc}",
                source_url=url,
            ) from exc

        self._update_rate_limit(response.headers)
        if response.status_code == 404:
            return None
        if (
            response.status_code == 403
            and response.headers.get("X-RateLimit-Remaining") == "0"
        ):
            raise GitHubAPIError(
                status_code=429,
                message=f"GitHub API rate limit exceeded while fetching {file_path}.",
                source_url=str(response.url),
            )
        if response.status_code >= 400:
            raise GitHubAPIError(
                status_code=response.status_code,
                message=f"GitHub Contents API error ({response.status_code}) for {file_path}: {response.text[:250]}",
                source_url=str(response.url),
            )

        fetched_at = datetime.now(UTC).isoformat()
        text_content = response.text
        actual_url = str(response.url)
        cache_created_at = (
            self._store_cache(
                cache_key, actual_url, response.status_code, text_content, fetched_at
            )
            if self.settings.cache_ttl_seconds > 0
            else fetched_at
        )
        return {
            "source": "github_rest_api",
            "source_url": actual_url,
            "http_status": response.status_code,
            "payload": text_content,
            "fetched_at": fetched_at,
            "cache_created_at": cache_created_at,
            "cached": False,
            "data_freshness": "live",
        }
