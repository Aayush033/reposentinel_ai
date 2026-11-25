"""Pydantic schemas for System B: OSV Vulnerability Service."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ProvenanceMeta(BaseModel):
    """Source and cache freshness metadata attached to every OSV/PyPI payload."""

    source: str
    source_url: str
    fetched_at: str
    http_status: int
    cached: bool
    cache_created_at: str
    data_freshness: str


class HealthResponse(BaseModel):
    """Health and cache summary for osv_service."""

    status: str
    service: str = "osv_service"
    port: int
    osv_api_base: str
    cache_db_path: str
    cached_entries: int
    registry_extension_active: bool = False
    timestamp: str


class DependencyQueryItem(BaseModel):
    """Single dependency item submitted for OSV batch vulnerability checking."""

    package_name: str = Field(
        ..., min_length=1, description="Package name (e.g. requests)"
    )
    ecosystem: str = Field(default="PyPI", description="OSV ecosystem (e.g. PyPI)")
    installed_version: str | None = Field(
        default=None,
        description="Exact installed version; if null, package is treated as unresolved and NOT queried against OSV",
    )


class BatchVulnerabilityRequest(BaseModel):
    """Request body for querying OSV batch API for a repository's dependencies."""

    dependencies: list[DependencyQueryItem] = Field(
        ...,
        description="List of dependencies to check against https://api.osv.dev/v1/querybatch",
    )
    include_details: bool = Field(
        default=True,
        description="Hydrate full vulnerability records from /v1/vulns/{id} for matched IDs",
    )


class SeverityRecord(BaseModel):
    """Severity entry exactly as supplied by OSV (never fabricated)."""

    type: str | None = None
    score: str | None = None
    label: str | None = None


class AffectedRangeRecord(BaseModel):
    """Affected version range and fixed versions extracted from OSV."""

    package_name: str | None = None
    ecosystem: str | None = None
    range_type: str | None = None
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)


class VulnerabilityReference(BaseModel):
    """External reference URL supplied by OSV."""

    type: str | None = None
    url: str


class VulnerabilityDetailResponse(BaseModel):
    """Full vulnerability details from OSV."""

    vulnerability_id: str
    summary: str | None = None
    details: str | None = None
    aliases: list[str] = Field(default_factory=list)
    affected_packages: list[str] = Field(default_factory=list)
    affected_ranges: list[AffectedRangeRecord] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    severity: list[SeverityRecord] = Field(default_factory=list)
    severity_label: str | None = Field(
        default=None,
        description="Supplier severity label (e.g. from database_specific.severity) if provided by OSV; null otherwise",
    )
    references: list[VulnerabilityReference] = Field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    osv_url: str
    provenance: ProvenanceMeta


class PackageVulnerabilityResult(BaseModel):
    """Vulnerability query outcome for one submitted dependency."""

    package_name: str
    ecosystem: str
    installed_version: str | None = None
    status: str = Field(
        ...,
        description="'vulnerable', 'no_known_vulnerabilities', or 'unresolved_skipped'",
    )
    vulnerability_ids: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityDetailResponse] = Field(default_factory=list)
    note: str | None = None


class BatchVulnerabilityResponse(BaseModel):
    """Aggregated OSV querybatch response across submitted dependencies."""

    total_submitted: int
    queried_count: int
    unresolved_skipped_count: int
    vulnerable_packages_count: int
    total_vulnerabilities_found: int
    results: list[PackageVulnerabilityResult]
    provenance: ProvenanceMeta


_COMMIT_SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


class CommitVulnerabilityRequest(BaseModel):
    """Request body for querying OSV.dev by exact Git commit SHA."""

    commit: str = Field(
        ...,
        min_length=40,
        max_length=64,
        description="Full Git commit SHA (40 hex chars for SHA-1 or 64 hex chars for SHA-256). Branch names and short SHAs are rejected.",
    )

    @field_validator("commit")
    @classmethod
    def validate_commit_sha(cls, value: str) -> str:
        cleaned = value.strip()
        if not _COMMIT_SHA_RE.match(cleaned):
            raise ValueError(
                "Invalid commit hash: must be a full 40-character (SHA-1) or 64-character (SHA-256) hexadecimal Git commit SHA."
            )
        return cleaned.lower()


class CommitVulnerabilityResponse(BaseModel):
    """OSV.dev commit-hash vulnerability lookup response with full provenance."""

    commit_hash: str
    vulnerability_count: int
    vulnerabilities: list[VulnerabilityDetailResponse] = Field(default_factory=list)
    source: str
    source_url: str
    fetched_at: str
    http_status: int
    cached: bool
    cache_created_at: str
    data_freshness: str
