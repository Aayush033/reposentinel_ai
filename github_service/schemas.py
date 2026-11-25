"""Pydantic schemas for the GitHub FastAPI service."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProvenanceMeta(BaseModel):
    """Source and cache freshness metadata attached to every API payload."""

    source: str = Field(
        default="github_rest_api", description="Upstream data source name"
    )
    source_url: str = Field(..., description="Exact upstream GitHub API URL")
    fetched_at: str = Field(
        ..., description="UTC ISO-8601 timestamp when upstream was fetched"
    )
    http_status: int = Field(..., description="HTTP status code returned by GitHub")
    cached: bool = Field(..., description="Whether this response was served from cache")
    cache_created_at: str = Field(
        ..., description="UTC ISO-8601 timestamp when cache entry was stored"
    )
    data_freshness: str = Field(
        ..., description="Freshness indicator (live or cached within TTL)"
    )


class HealthResponse(BaseModel):
    """Service health and GitHub API configuration status."""

    status: str
    service: str = "github_service"
    port: int
    github_api_base: str
    token_configured: bool
    cache_db_path: str
    cached_entries: int
    last_rate_limit_remaining: int | None = None
    last_rate_limit_reset: str | None = None
    timestamp: str


class RepositoryMetadataResponse(BaseModel):
    """Real GitHub repository metadata."""

    owner: str
    repo: str
    full_name: str
    description: str | None = None
    private: bool
    default_branch: str
    language: str | None = None
    stargazers_count: int
    forks_count: int
    open_issues_count: int
    topics: list[str] = Field(default_factory=list)
    license_name: str | None = None
    html_url: str
    created_at: str
    updated_at: str
    pushed_at: str | None = None
    archived: bool
    provenance: ProvenanceMeta


class DependencyRecord(BaseModel):
    """Parsed dependency entry with strict version resolution tracking."""

    package_name: str
    normalized_name: str
    ecosystem: str = "PyPI"
    installed_version: str | None = Field(
        default=None,
        description="Exact pinned version if explicitly specified, otherwise null",
    )
    version_specifier: str | None = Field(
        default=None,
        description="Original version constraint or specifier if present",
    )
    is_resolved: bool = Field(
        ...,
        description="True only when pinned to an exact version; False for ranges or unpinned specs",
    )
    resolution_status: str = Field(
        ...,
        description="'pinned' when exact version is known, 'unresolved' otherwise",
    )
    manifest_path: str
    manifest_type: str
    raw_requirement: str
    source_url: str


class RepositoryDependenciesResponse(BaseModel):
    """Parsed dependencies from real repository manifest files."""

    owner: str
    repo: str
    default_branch: str
    manifests_checked: list[str]
    manifests_found: list[str]
    total_dependencies: int
    resolved_count: int
    unresolved_count: int
    dependencies: list[DependencyRecord]
    provenance: ProvenanceMeta


class GitHubIssueRecord(BaseModel):
    """Actual GitHub issue record."""

    id: int
    number: int
    title: str
    state: str
    body: str | None = None
    author: str | None = None
    labels: list[str] = Field(default_factory=list)
    comments: int
    html_url: str
    created_at: str
    updated_at: str
    closed_at: str | None = None


class RepositoryIssuesResponse(BaseModel):
    """Paginated list of real GitHub issues."""

    owner: str
    repo: str
    state: str
    page: int
    per_page: int
    count: int
    issues: list[GitHubIssueRecord]
    provenance: ProvenanceMeta


class GitHubPullRequestRecord(BaseModel):
    """Actual GitHub pull request record."""

    id: int
    number: int
    title: str
    state: str
    draft: bool = False
    body: str | None = None
    author: str | None = None
    labels: list[str] = Field(default_factory=list)
    head_ref: str | None = None
    base_ref: str | None = None
    html_url: str
    created_at: str
    updated_at: str
    closed_at: str | None = None
    merged_at: str | None = None


class RepositoryPullsResponse(BaseModel):
    """Paginated list of real GitHub pull requests."""

    owner: str
    repo: str
    state: str
    page: int
    per_page: int
    count: int
    pull_requests: list[GitHubPullRequestRecord]
    provenance: ProvenanceMeta


class GitHubCommitRecord(BaseModel):
    """Actual GitHub commit record."""

    sha: str
    short_sha: str
    message: str
    author_name: str | None = None
    author_login: str | None = None
    authored_at: str | None = None
    html_url: str


class RepositoryCommitsResponse(BaseModel):
    """Paginated list of real GitHub commits."""

    owner: str
    repo: str
    sha: str | None = None
    page: int
    per_page: int
    count: int
    commits: list[GitHubCommitRecord]
    provenance: ProvenanceMeta
