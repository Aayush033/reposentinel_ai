"""FastAPI application for System B: OSV Vulnerability Service."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException

from .config import get_settings
from .osv_client import OSVAPIError, OSVClient
from .schemas import (
    BatchVulnerabilityRequest,
    BatchVulnerabilityResponse,
    CommitVulnerabilityRequest,
    CommitVulnerabilityResponse,
    HealthResponse,
    PackageVulnerabilityResult,
    ProvenanceMeta,
    VulnerabilityDetailResponse,
)

settings = get_settings()
osv_client = OSVClient(settings)

app = FastAPI(
    title="RepoSentinel OSV Vulnerability Service",
    description="System B: Real-time OSV.dev vulnerability querying and advisory detail service.",
    version="1.0.0",
)

from demo_extensions.pypi_registry_router import router as pypi_registry_router
from osv_service.package_registry import fetch_pypi_latest_release, PyPIAPIError

@app.get("/registry/pypi/{package_name}/latest-release", summary="Get the latest published release for a PyPI package")
async def get_pypi_latest_release(package_name: str):
    """Query https://pypi.org/pypi/{package_name}/json for the real latest published version."""
    try:
        return await fetch_pypi_latest_release(package_name)
    except PyPIAPIError as err:
        raise HTTPException(status_code=err.status_code, detail={"error": err.message, "source_url": err.source_url})


def _raise_http(err: OSVAPIError) -> None:
    raise HTTPException(
        status_code=err.status_code,
        detail={"error": err.message, "source_url": err.source_url},
    ) from err


@app.get("/health", response_model=HealthResponse, summary="Check OSV service health")
async def health() -> HealthResponse:
    """Return operational health, OSV upstream URL, and cache statistics."""
    route_paths: set[str] = set()
    for route in app.routes:
        if getattr(route, "path", None):
            route_paths.add(str(route.path))
        if hasattr(route, "original_router") and hasattr(
            route.original_router, "routes"
        ):
            for sub in route.original_router.routes:
                if getattr(sub, "path", None):
                    route_paths.add(str(sub.path))
    registry_active = "/registry/pypi/{package_name}/latest-release" in route_paths
    return HealthResponse(
        status="ok",
        port=settings.port,
        osv_api_base=settings.osv_api_base,
        cache_db_path=str(settings.cache_db_path),
        cached_entries=osv_client.count_cached_entries(),
        registry_extension_active=registry_active,
        timestamp=datetime.now(UTC).isoformat(),
    )


@app.post(
    "/vulnerabilities/query-batch",
    response_model=BatchVulnerabilityResponse,
    summary="Query OSV.dev batch API for exact dependency versions",
)
async def query_vulnerabilities_batch(
    request: BatchVulnerabilityRequest,
) -> BatchVulnerabilityResponse:
    """Submit exact pinned dependencies to POST https://api.osv.dev/v1/querybatch.

    Unresolved dependencies without an exact version are never guessed or classified as safe/vulnerable.
    """
    if not request.dependencies:
        now_iso = datetime.now(UTC).isoformat()
        return BatchVulnerabilityResponse(
            total_submitted=0,
            queried_count=0,
            unresolved_skipped_count=0,
            vulnerable_packages_count=0,
            total_vulnerabilities_found=0,
            results=[],
            provenance=ProvenanceMeta(
                source="osv_api",
                source_url=f"{settings.osv_api_base}/v1/querybatch",
                fetched_at=now_iso,
                http_status=200,
                cached=False,
                cache_created_at=now_iso,
                data_freshness="live (empty dependency list)",
            ),
        )

    queried_indices: list[int] = []
    osv_queries: list[dict[str, object]] = []
    results: list[PackageVulnerabilityResult | None] = [None] * len(
        request.dependencies
    )

    for idx, dep in enumerate(request.dependencies):
        exact_ver = (dep.installed_version or "").strip()
        if not exact_ver:
            results[idx] = PackageVulnerabilityResult(
                package_name=dep.package_name,
                ecosystem=dep.ecosystem,
                installed_version=None,
                status="unresolved_skipped",
                vulnerability_ids=[],
                vulnerabilities=[],
                note="Skipped OSV query because installed_version is unresolved (not pinned to an exact version).",
            )
            continue

        queried_indices.append(idx)
        osv_queries.append(
            {
                "version": exact_ver,
                "package": {
                    "name": dep.package_name,
                    "ecosystem": dep.ecosystem,
                },
            }
        )

    if not osv_queries:
        now_iso = datetime.now(UTC).isoformat()
        finalized = [item for item in results if item is not None]
        return BatchVulnerabilityResponse(
            total_submitted=len(request.dependencies),
            queried_count=0,
            unresolved_skipped_count=len(finalized),
            vulnerable_packages_count=0,
            total_vulnerabilities_found=0,
            results=finalized,
            provenance=ProvenanceMeta(
                source="osv_api",
                source_url=f"{settings.osv_api_base}/v1/querybatch",
                fetched_at=now_iso,
                http_status=200,
                cached=False,
                cache_created_at=now_iso,
                data_freshness="live (no pinned versions to query)",
            ),
        )

    try:
        batch_res = await osv_client.query_batch(osv_queries)
    except OSVAPIError as err:
        _raise_http(err)

    batch_payload = batch_res["payload"]
    batch_items = batch_payload.get("results") or []

    matched_ids_per_idx: dict[int, list[str]] = {}
    all_vuln_ids: list[str] = []

    for q_pos, dep_idx in enumerate(queried_indices):
        item = batch_items[q_pos] if q_pos < len(batch_items) else {}
        vulns = item.get("vulns") or []
        ids = [str(v["id"]) for v in vulns if isinstance(v, dict) and v.get("id")]
        matched_ids_per_idx[dep_idx] = ids
        all_vuln_ids.extend(ids)

    hydrated: dict[str, VulnerabilityDetailResponse] = {}
    if request.include_details and all_vuln_ids:
        try:
            hydrated = await osv_client.get_vulnerabilities_many(all_vuln_ids)
        except OSVAPIError as err:
            _raise_http(err)

    vulnerable_packages_count = 0
    total_vulns_found = 0
    for dep_idx in queried_indices:
        dep = request.dependencies[dep_idx]
        ids = matched_ids_per_idx.get(dep_idx, [])
        if ids:
            vulnerable_packages_count += 1
            total_vulns_found += len(ids)
        details_list = [hydrated[vid] for vid in ids if vid in hydrated]
        results[dep_idx] = PackageVulnerabilityResult(
            package_name=dep.package_name,
            ecosystem=dep.ecosystem,
            installed_version=dep.installed_version,
            status="vulnerable" if ids else "no_known_vulnerabilities",
            vulnerability_ids=ids,
            vulnerabilities=details_list,
        )

    finalized_results = [item for item in results if item is not None]
    return BatchVulnerabilityResponse(
        total_submitted=len(request.dependencies),
        queried_count=len(queried_indices),
        unresolved_skipped_count=len(request.dependencies) - len(queried_indices),
        vulnerable_packages_count=vulnerable_packages_count,
        total_vulnerabilities_found=total_vulns_found,
        results=finalized_results,
        provenance=ProvenanceMeta(
            source=batch_res["source"],
            source_url=batch_res["source_url"],
            fetched_at=batch_res["fetched_at"],
            http_status=batch_res["http_status"],
            cached=batch_res["cached"],
            cache_created_at=batch_res["cache_created_at"],
            data_freshness=batch_res["data_freshness"],
        ),
    )


@app.get(
    "/vulnerabilities/{vulnerability_id}",
    response_model=VulnerabilityDetailResponse,
    summary="Get full vulnerability advisory details from OSV.dev",
)
async def get_vulnerability_details(
    vulnerability_id: str,
) -> VulnerabilityDetailResponse:
    """Retrieve complete vulnerability advisory data from GET https://api.osv.dev/v1/vulns/{vulnerability_id}."""
    try:
        return await osv_client.get_vulnerability(vulnerability_id.strip())
    except OSVAPIError as err:
        _raise_http(err)


@app.post(
    "/vulnerabilities/query-commit",
    response_model=CommitVulnerabilityResponse,
    summary="Query OSV.dev vulnerabilities by exact Git commit SHA",
)
async def query_vulnerabilities_by_commit(
    request: CommitVulnerabilityRequest,
) -> CommitVulnerabilityResponse:
    """Perform a real OSV commit-hash vulnerability lookup via POST https://api.osv.dev/v1/query.

    Accepts a full 40-character (or 64-character) hexadecimal Git commit SHA and
    returns any OSV vulnerability records associated with that commit, with full
    provenance and pagination support. Separate from dependency-version scanning.
    """
    try:
        return await osv_client.query_commit(request.commit)
    except OSVAPIError as err:
        _raise_http(err)
