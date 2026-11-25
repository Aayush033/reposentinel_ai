"""Real OSV.dev API client with SQLite caching and strict no-fabrication parsing."""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import OSVServiceSettings
from .schemas import (
    AffectedRangeRecord,
    CommitVulnerabilityResponse,
    ProvenanceMeta,
    SeverityRecord,
    VulnerabilityDetailResponse,
    VulnerabilityReference,
)

_COMMIT_SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_MAX_COMMIT_PAGES = 20


class OSVAPIError(Exception):
    """Raised when api.osv.dev fails or returns an error status."""

    def __init__(self, status_code: int, message: str, source_url: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.source_url = source_url


def parse_osv_vulnerability(
    vuln: dict[str, Any],
    provenance: ProvenanceMeta,
) -> VulnerabilityDetailResponse:
    """Parse an official OSV vulnerability JSON object without inventing scores or fixes."""
    vuln_id = str(vuln.get("id", ""))
    affected_packages: list[str] = []
    affected_ranges: list[AffectedRangeRecord] = []
    fixed_versions: list[str] = []

    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        pkg_name = pkg.get("name")
        pkg_eco = pkg.get("ecosystem")
        if isinstance(pkg_name, str) and pkg_name not in affected_packages:
            affected_packages.append(pkg_name)

        explicit_versions = [
            str(v)
            for v in (aff.get("versions") or [])
            if isinstance(v, (str, int, float))
        ]
        ranges = aff.get("ranges") or []
        if not ranges and explicit_versions:
            affected_ranges.append(
                AffectedRangeRecord(
                    package_name=pkg_name,
                    ecosystem=pkg_eco,
                    versions=explicit_versions[:50],
                )
            )
            continue

        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            events = [ev for ev in (rng.get("events") or []) if isinstance(ev, dict)]
            introduced = None
            fixed = None
            last_affected = None
            for ev in events:
                if "introduced" in ev and introduced is None:
                    introduced = str(ev["introduced"])
                if "fixed" in ev:
                    fixed_val = str(ev["fixed"])
                    fixed = fixed_val
                    if fixed_val not in fixed_versions:
                        fixed_versions.append(fixed_val)
                if "last_affected" in ev:
                    last_affected = str(ev["last_affected"])
            affected_ranges.append(
                AffectedRangeRecord(
                    package_name=pkg_name,
                    ecosystem=pkg_eco,
                    range_type=rng.get("type"),
                    introduced=introduced,
                    fixed=fixed,
                    last_affected=last_affected,
                    events=events,
                    versions=explicit_versions[:50],
                )
            )

    severity_records: list[SeverityRecord] = []
    for sev in vuln.get("severity") or []:
        if isinstance(sev, dict):
            severity_records.append(
                SeverityRecord(
                    type=sev.get("type"),
                    score=sev.get("score"),
                )
            )

    db_specific = vuln.get("database_specific") or {}
    severity_label = None
    if isinstance(db_specific, dict):
        raw_sev = db_specific.get("severity")
        if isinstance(raw_sev, str) and raw_sev.strip():
            severity_label = raw_sev.strip().upper()
    if severity_label is None:
        # Check affected[].database_specific or ecosystem_specific if present
        for aff in vuln.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            eco_spec = aff.get("ecosystem_specific") or {}
            if isinstance(eco_spec, dict) and isinstance(eco_spec.get("severity"), str):
                severity_label = eco_spec["severity"].strip().upper()
                break

    refs: list[VulnerabilityReference] = []
    for ref in vuln.get("references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            refs.append(VulnerabilityReference(type=ref.get("type"), url=ref["url"]))

    return VulnerabilityDetailResponse(
        vulnerability_id=vuln_id,
        summary=vuln.get("summary"),
        details=vuln.get("details"),
        aliases=[str(a) for a in (vuln.get("aliases") or [])],
        affected_packages=affected_packages,
        affected_ranges=affected_ranges,
        fixed_versions=fixed_versions,
        severity=severity_records,
        severity_label=severity_label,
        references=refs,
        published=vuln.get("published"),
        modified=vuln.get("modified"),
        withdrawn=vuln.get("withdrawn"),
        osv_url=f"https://osv.dev/vulnerability/{vuln_id}",
        provenance=provenance,
    )


class OSVClient:
    """Async client for https://api.osv.dev with SQLite response caching."""

    def __init__(self, settings: OSVServiceSettings) -> None:
        self.settings = settings
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
            "cached": True,
            "data_freshness": f"cached (expires_at={row[6]})",
        }

    def _store_cache(
        self,
        cache_key: str,
        source: str,
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
                    source,
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

    async def query_batch(self, queries: list[dict[str, Any]]) -> dict[str, Any]:
        """Call POST https://api.osv.dev/v1/querybatch with exact package/ecosystem/version queries."""
        url = f"{self.settings.osv_api_base}/v1/querybatch"
        body = {"queries": queries}
        cache_key = f"POST:{url}:{json.dumps(body, sort_keys=True)}"

        if self.settings.cache_ttl_seconds > 0:
            cached = self._get_cached(cache_key)
            if cached is not None:
                return cached

        try:
            async with httpx.AsyncClient(
                timeout=self.settings.request_timeout_seconds
            ) as client:
                response = await client.post(url, json=body)
        except httpx.TimeoutException as exc:
            raise OSVAPIError(
                status_code=504,
                message=f"OSV batch API timed out after {self.settings.request_timeout_seconds}s: {exc}",
                source_url=url,
            ) from exc
        except httpx.HTTPError as exc:
            raise OSVAPIError(
                status_code=502,
                message=f"Network error contacting OSV batch API: {exc}",
                source_url=url,
            ) from exc

        fetched_at = datetime.now(UTC).isoformat()
        if response.status_code >= 400:
            raise OSVAPIError(
                status_code=response.status_code,
                message=f"OSV batch API returned HTTP {response.status_code}: {response.text[:300]}",
                source_url=url,
            )

        payload = response.json()
        cache_created_at = (
            self._store_cache(
                cache_key, "osv_api", url, response.status_code, payload, fetched_at
            )
            if self.settings.cache_ttl_seconds > 0
            else fetched_at
        )
        return {
            "source": "osv_api",
            "source_url": url,
            "http_status": response.status_code,
            "payload": payload,
            "fetched_at": fetched_at,
            "cache_created_at": cache_created_at,
            "cached": False,
            "data_freshness": "live",
        }

    async def get_vulnerability(
        self, vulnerability_id: str
    ) -> VulnerabilityDetailResponse:
        """Fetch full vulnerability details from GET https://api.osv.dev/v1/vulns/{id}."""
        url = f"{self.settings.osv_api_base}/v1/vulns/{vulnerability_id}"
        cache_key = f"GET:{url}"

        if self.settings.cache_ttl_seconds > 0:
            cached = self._get_cached(cache_key)
            if cached is not None:
                prov = ProvenanceMeta(
                    source=cached["source"],
                    source_url=cached["source_url"],
                    fetched_at=cached["fetched_at"],
                    http_status=cached["http_status"],
                    cached=True,
                    cache_created_at=cached["cache_created_at"],
                    data_freshness=cached["data_freshness"],
                )
                return parse_osv_vulnerability(cached["payload"], prov)

        try:
            async with httpx.AsyncClient(
                timeout=self.settings.request_timeout_seconds
            ) as client:
                response = await client.get(url)
        except httpx.TimeoutException as exc:
            raise OSVAPIError(
                status_code=504,
                message=f"OSV vulnerability API timed out for {vulnerability_id}: {exc}",
                source_url=url,
            ) from exc
        except httpx.HTTPError as exc:
            raise OSVAPIError(
                status_code=502,
                message=f"Network error fetching {vulnerability_id} from OSV: {exc}",
                source_url=url,
            ) from exc

        fetched_at = datetime.now(UTC).isoformat()
        if response.status_code == 404:
            raise OSVAPIError(
                status_code=404,
                message=f"Vulnerability '{vulnerability_id}' not found in OSV.",
                source_url=url,
            )
        if response.status_code >= 400:
            raise OSVAPIError(
                status_code=response.status_code,
                message=f"OSV vulnerability API returned HTTP {response.status_code}: {response.text[:300]}",
                source_url=url,
            )

        payload = response.json()
        cache_created_at = (
            self._store_cache(
                cache_key, "osv_api", url, response.status_code, payload, fetched_at
            )
            if self.settings.cache_ttl_seconds > 0
            else fetched_at
        )
        prov = ProvenanceMeta(
            source="osv_api",
            source_url=url,
            fetched_at=fetched_at,
            http_status=response.status_code,
            cached=False,
            cache_created_at=cache_created_at,
            data_freshness="live",
        )
        return parse_osv_vulnerability(payload, prov)

    async def get_vulnerabilities_many(
        self, vulnerability_ids: list[str]
    ) -> dict[str, VulnerabilityDetailResponse]:
        """Hydrate multiple unique OSV vulnerability IDs concurrently with bounded concurrency."""
        unique_ids = list(dict.fromkeys(vulnerability_ids))
        semaphore = asyncio.Semaphore(8)

        async def _fetch_one(vid: str) -> tuple[str, VulnerabilityDetailResponse]:
            async with semaphore:
                return vid, await self.get_vulnerability(vid)

        pairs = await asyncio.gather(*(_fetch_one(vid) for vid in unique_ids))
        return dict(pairs)

    @staticmethod
    def validate_commit_hash(
        commit_hash: str,
        api_base: str = "https://api.osv.dev",
    ) -> str:
        """Validate that input is a non-empty full 40-char or 64-char hex Git commit SHA."""
        cleaned = (commit_hash or "").strip()
        if not cleaned or not _COMMIT_SHA_RE.match(cleaned):
            raise OSVAPIError(
                status_code=422,
                message=(
                    "Invalid commit hash: provide a full 40-character (SHA-1) or 64-character (SHA-256) "
                    "hexadecimal Git commit SHA. Branch names, messages, and short SHAs are not accepted."
                ),
                source_url=f"{api_base}/v1/query",
            )
        return cleaned.lower()

    async def query_commit(self, commit_hash: str) -> CommitVulnerabilityResponse:
        """Query POST https://api.osv.dev/v1/query for vulnerabilities matching an exact Git commit SHA."""
        sha = self.validate_commit_hash(commit_hash, self.settings.osv_api_base)
        url = f"{self.settings.osv_api_base}/v1/query"
        cache_key = f"POST:{url}:commit={sha}"

        if self.settings.cache_ttl_seconds > 0:
            cached = self._get_cached(cache_key)
            if cached is not None:
                prov = ProvenanceMeta(
                    source=cached["source"],
                    source_url=cached["source_url"],
                    fetched_at=cached["fetched_at"],
                    http_status=cached["http_status"],
                    cached=True,
                    cache_created_at=cached["cache_created_at"],
                    data_freshness=cached["data_freshness"],
                )
                raw_vulns = cached["payload"].get("vulns") or []
                parsed = [
                    parse_osv_vulnerability(v, prov)
                    for v in raw_vulns
                    if isinstance(v, dict)
                ]
                return CommitVulnerabilityResponse(
                    commit_hash=sha,
                    vulnerability_count=len(parsed),
                    vulnerabilities=parsed,
                    source=cached["source"],
                    source_url=cached["source_url"],
                    fetched_at=cached["fetched_at"],
                    http_status=cached["http_status"],
                    cached=True,
                    cache_created_at=cached["cache_created_at"],
                    data_freshness=cached["data_freshness"],
                )

        all_raw_vulns: list[dict[str, Any]] = []
        seen_tokens: set[str] = set()
        page_token: str | None = None
        last_status = 200

        async with httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds
        ) as client:
            for _ in range(_MAX_COMMIT_PAGES):
                body: dict[str, Any] = {"commit": sha}
                if page_token:
                    body["page_token"] = page_token
                try:
                    response = await client.post(url, json=body)
                except httpx.TimeoutException as exc:
                    raise OSVAPIError(
                        status_code=504,
                        message=f"OSV commit query timed out after {self.settings.request_timeout_seconds}s: {exc}",
                        source_url=url,
                    ) from exc
                except httpx.HTTPError as exc:
                    raise OSVAPIError(
                        status_code=502,
                        message=f"Network error contacting OSV commit query API: {exc}",
                        source_url=url,
                    ) from exc

                last_status = response.status_code
                if response.status_code >= 400:
                    raise OSVAPIError(
                        status_code=response.status_code,
                        message=f"OSV commit query API returned HTTP {response.status_code}: {response.text[:300]}",
                        source_url=url,
                    )

                page_payload = response.json()
                vulns = page_payload.get("vulns") or []
                for v in vulns:
                    if isinstance(v, dict):
                        all_raw_vulns.append(v)

                next_token = page_payload.get("next_page_token")
                if not next_token or next_token in seen_tokens:
                    break
                seen_tokens.add(str(next_token))
                page_token = str(next_token)

        fetched_at = datetime.now(UTC).isoformat()
        combined_payload = {"vulns": all_raw_vulns}
        cache_created_at = (
            self._store_cache(
                cache_key,
                "osv_api",
                url,
                last_status,
                combined_payload,
                fetched_at,
            )
            if self.settings.cache_ttl_seconds > 0
            else fetched_at
        )
        prov = ProvenanceMeta(
            source="osv_api",
            source_url=url,
            fetched_at=fetched_at,
            http_status=last_status,
            cached=False,
            cache_created_at=cache_created_at,
            data_freshness="live",
        )
        parsed_vulns = [parse_osv_vulnerability(v, prov) for v in all_raw_vulns]
        return CommitVulnerabilityResponse(
            commit_hash=sha,
            vulnerability_count=len(parsed_vulns),
            vulnerabilities=parsed_vulns,
            source="osv_api",
            source_url=url,
            fetched_at=fetched_at,
            http_status=last_status,
            cached=False,
            cache_created_at=cache_created_at,
            data_freshness="live",
        )
