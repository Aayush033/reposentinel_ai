"""FastAPI application for System A: GitHub Repository & Manifest Service."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse

from .config import get_settings
from .dependency_parser import (
    merge_dependency_records,
    parse_lockfile_toml,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from .github_client import GitHubAPIError, GitHubClient
from .schemas import (
    DependencyRecord,
    GitHubCommitRecord,
    GitHubIssueRecord,
    GitHubPullRequestRecord,
    HealthResponse,
    ProvenanceMeta,
    RepositoryCommitsResponse,
    RepositoryDependenciesResponse,
    RepositoryIssuesResponse,
    RepositoryMetadataResponse,
    RepositoryPullsResponse,
)

SUPPORTED_MANIFESTS = [
    "uv.lock",
    "poetry.lock",
    "requirements.txt",
    "pyproject.toml",
    "requirements/base.txt",
    "requirements/prod.txt",
]

settings = get_settings()
github_client = GitHubClient(settings)

app = FastAPI(
    title="RepoSentinel GitHub Service",
    description="System A: Real-time GitHub REST API repository, dependency manifest, issue, PR, and commit service.",
    version="1.0.0",
)


@app.get("/", include_in_schema=False)
async def root():
    """Redirect root access to interactive OpenAPI docs."""
    return RedirectResponse(url="/docs")


def _to_provenance(result: dict) -> ProvenanceMeta:
    return ProvenanceMeta(
        source=result["source"],
        source_url=result["source_url"],
        fetched_at=result["fetched_at"],
        http_status=result["http_status"],
        cached=result["cached"],
        cache_created_at=result["cache_created_at"],
        data_freshness=result["data_freshness"],
    )


def _raise_http(err: GitHubAPIError) -> None:
    raise HTTPException(
        status_code=err.status_code,
        detail={"error": err.message, "source_url": err.source_url},
    ) from err


@app.get(
    "/health", response_model=HealthResponse, summary="Check GitHub service health"
)
async def health() -> HealthResponse:
    """Return operational health, token configuration status, and cache statistics."""
    return HealthResponse(
        status="ok",
        port=settings.port,
        github_api_base=settings.github_api_base,
        token_configured=bool(settings.github_token),
        cache_db_path=str(settings.cache_db_path),
        cached_entries=github_client.count_cached_entries(),
        last_rate_limit_remaining=github_client.last_rate_limit_remaining,
        last_rate_limit_reset=github_client.last_rate_limit_reset,
        timestamp=datetime.now(UTC).isoformat(),
    )


@app.get(
    "/repos/{owner}/{repo}",
    response_model=RepositoryMetadataResponse,
    summary="Get real GitHub repository metadata",
)
async def get_repository(owner: str, repo: str) -> RepositoryMetadataResponse:
    """Retrieve live repository metadata from https://api.github.com/repos/{owner}/{repo}."""
    try:
        result = await github_client.get_json(f"/repos/{owner}/{repo}")
    except GitHubAPIError as err:
        _raise_http(err)

    data = result["payload"]
    license_obj = data.get("license") or {}
    return RepositoryMetadataResponse(
        owner=owner,
        repo=repo,
        full_name=data["full_name"],
        description=data.get("description"),
        private=bool(data.get("private", False)),
        default_branch=data.get("default_branch", "main"),
        language=data.get("language"),
        stargazers_count=int(data.get("stargazers_count", 0)),
        forks_count=int(data.get("forks_count", 0)),
        open_issues_count=int(data.get("open_issues_count", 0)),
        topics=list(data.get("topics") or []),
        license_name=license_obj.get("spdx_id") or license_obj.get("name"),
        html_url=data["html_url"],
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        pushed_at=data.get("pushed_at"),
        archived=bool(data.get("archived", False)),
        provenance=_to_provenance(result),
    )


@app.get(
    "/repos/{owner}/{repo}/dependencies",
    response_model=RepositoryDependenciesResponse,
    summary="Parse real dependency manifests for a GitHub repository",
)
async def get_repository_dependencies(
    owner: str, repo: str
) -> RepositoryDependenciesResponse:
    """Fetch requirements.txt, pyproject.toml, poetry.lock, and uv.lock from GitHub and parse exact vs unresolved versions."""
    try:
        repo_result = await github_client.get_json(f"/repos/{owner}/{repo}")
    except GitHubAPIError as err:
        _raise_http(err)

    repo_data = repo_result["payload"]
    default_branch = repo_data.get("default_branch", "main")

    # Inspect root directory contents first so we only download manifests that actually exist.
    try:
        root_listing = await github_client.get_json(
            f"/repos/{owner}/{repo}/contents",
            params={"ref": default_branch},
        )
    except GitHubAPIError as err:
        _raise_http(err)

    root_items = (
        root_listing["payload"] if isinstance(root_listing["payload"], list) else []
    )
    root_names = {
        item.get("name"): item for item in root_items if isinstance(item, dict)
    }

    candidate_paths: list[str] = []
    for manifest_name in (
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
        "pyproject.toml",
    ):
        if manifest_name in root_names:
            candidate_paths.append(manifest_name)

    if "requirements" in root_names and root_names["requirements"].get("type") == "dir":
        try:
            req_dir = await github_client.get_json(
                f"/repos/{owner}/{repo}/contents/requirements",
                params={"ref": default_branch},
            )
            if isinstance(req_dir["payload"], list):
                for item in req_dir["payload"]:
                    if isinstance(item, dict) and str(item.get("name", "")).endswith(
                        ".txt"
                    ):
                        candidate_paths.append(f"requirements/{item['name']}")
        except GitHubAPIError:
            pass

    manifests_checked = list(dict.fromkeys(SUPPORTED_MANIFESTS + candidate_paths))
    manifests_found: list[str] = []
    all_records: list[DependencyRecord] = []

    for path in candidate_paths:
        try:
            raw_res = await github_client.get_raw_file(
                owner, repo, path, ref=default_branch
            )
        except GitHubAPIError as err:
            _raise_http(err)
        if raw_res is None:
            continue

        manifests_found.append(path)
        content = str(raw_res["payload"])
        source_url = raw_res["source_url"]

        if path.endswith(".txt"):
            all_records.extend(parse_requirements_txt(content, path, source_url))
        elif path == "pyproject.toml":
            all_records.extend(parse_pyproject_toml(content, path, source_url))
        elif path == "poetry.lock":
            all_records.extend(
                parse_lockfile_toml(content, path, "poetry.lock", source_url)
            )
        elif path == "uv.lock":
            all_records.extend(
                parse_lockfile_toml(
                    content, path, "uv.lock", source_url, root_project_name=repo
                )
            )

    merged = merge_dependency_records(all_records)
    resolved_count = sum(1 for item in merged if item.is_resolved)
    unresolved_count = len(merged) - resolved_count

    return RepositoryDependenciesResponse(
        owner=owner,
        repo=repo,
        default_branch=default_branch,
        manifests_checked=manifests_checked,
        manifests_found=manifests_found,
        total_dependencies=len(merged),
        resolved_count=resolved_count,
        unresolved_count=unresolved_count,
        dependencies=merged,
        provenance=_to_provenance(root_listing),
    )


@app.get(
    "/repos/{owner}/{repo}/issues",
    response_model=RepositoryIssuesResponse,
    summary="List real GitHub issues for a repository",
)
async def get_repository_issues(
    owner: str,
    repo: str,
    state: Literal["open", "closed", "all"] = Query(
        default="open", description="Issue state filter"
    ),
    page: int = Query(default=1, ge=1, le=100, description="Result page number"),
    per_page: int = Query(default=30, ge=1, le=100, description="Items per page"),
) -> RepositoryIssuesResponse:
    """Retrieve real GitHub issues (excluding pull requests) with state and pagination support."""
    try:
        result = await github_client.get_json(
            f"/repos/{owner}/{repo}/issues",
            params={"state": state, "page": page, "per_page": per_page},
        )
    except GitHubAPIError as err:
        _raise_http(err)

    issues: list[GitHubIssueRecord] = []
    for item in result["payload"]:
        # GitHub's /issues endpoint includes PRs with a 'pull_request' key; keep genuine issues only.
        if "pull_request" in item:
            continue
        user_obj = item.get("user") or {}
        labels = [
            lbl.get("name", "")
            for lbl in (item.get("labels") or [])
            if isinstance(lbl, dict)
        ]
        body_text = item.get("body")
        if isinstance(body_text, str) and len(body_text) > 2500:
            body_text = body_text[:2500] + "..."
        issues.append(
            GitHubIssueRecord(
                id=int(item["id"]),
                number=int(item["number"]),
                title=item["title"],
                state=item["state"],
                body=body_text,
                author=user_obj.get("login"),
                labels=[name for name in labels if name],
                comments=int(item.get("comments", 0)),
                html_url=item["html_url"],
                created_at=item["created_at"],
                updated_at=item["updated_at"],
                closed_at=item.get("closed_at"),
            )
        )

    return RepositoryIssuesResponse(
        owner=owner,
        repo=repo,
        state=state,
        page=page,
        per_page=per_page,
        count=len(issues),
        issues=issues,
        provenance=_to_provenance(result),
    )


@app.get(
    "/repos/{owner}/{repo}/pulls",
    response_model=RepositoryPullsResponse,
    summary="List real GitHub pull requests for a repository",
)
async def get_repository_pulls(
    owner: str,
    repo: str,
    state: Literal["open", "closed", "all"] = Query(
        default="open", description="Pull request state filter"
    ),
    page: int = Query(default=1, ge=1, le=100, description="Result page number"),
    per_page: int = Query(default=30, ge=1, le=100, description="Items per page"),
) -> RepositoryPullsResponse:
    """Retrieve real GitHub pull requests with state and pagination support."""
    try:
        result = await github_client.get_json(
            f"/repos/{owner}/{repo}/pulls",
            params={"state": state, "page": page, "per_page": per_page},
        )
    except GitHubAPIError as err:
        _raise_http(err)

    pulls: list[GitHubPullRequestRecord] = []
    for item in result["payload"]:
        user_obj = item.get("user") or {}
        head_obj = item.get("head") or {}
        base_obj = item.get("base") or {}
        labels = [
            lbl.get("name", "")
            for lbl in (item.get("labels") or [])
            if isinstance(lbl, dict)
        ]
        body_text = item.get("body")
        if isinstance(body_text, str) and len(body_text) > 2500:
            body_text = body_text[:2500] + "..."
        pulls.append(
            GitHubPullRequestRecord(
                id=int(item["id"]),
                number=int(item["number"]),
                title=item["title"],
                state=item["state"],
                draft=bool(item.get("draft", False)),
                body=body_text,
                author=user_obj.get("login"),
                labels=[name for name in labels if name],
                head_ref=head_obj.get("ref"),
                base_ref=base_obj.get("ref"),
                html_url=item["html_url"],
                created_at=item["created_at"],
                updated_at=item["updated_at"],
                closed_at=item.get("closed_at"),
                merged_at=item.get("merged_at"),
            )
        )

    return RepositoryPullsResponse(
        owner=owner,
        repo=repo,
        state=state,
        page=page,
        per_page=per_page,
        count=len(pulls),
        pull_requests=pulls,
        provenance=_to_provenance(result),
    )


@app.get(
    "/repos/{owner}/{repo}/commits",
    response_model=RepositoryCommitsResponse,
    summary="List real GitHub commits for a repository",
)
async def get_repository_commits(
    owner: str,
    repo: str,
    sha: str | None = Query(
        default=None, description="Optional branch name or commit SHA"
    ),
    page: int = Query(default=1, ge=1, le=100, description="Result page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Items per page"),
) -> RepositoryCommitsResponse:
    """Retrieve real GitHub commit history for a repository."""
    params: dict[str, object] = {"page": page, "per_page": per_page}
    if sha:
        params["sha"] = sha
    try:
        result = await github_client.get_json(
            f"/repos/{owner}/{repo}/commits", params=params
        )
    except GitHubAPIError as err:
        _raise_http(err)

    commits: list[GitHubCommitRecord] = []
    for item in result["payload"]:
        commit_obj = item.get("commit") or {}
        author_meta = commit_obj.get("author") or {}
        author_user = item.get("author") or {}
        full_sha = item["sha"]
        commits.append(
            GitHubCommitRecord(
                sha=full_sha,
                short_sha=full_sha[:7],
                message=str(commit_obj.get("message") or "").splitlines()[0],
                author_name=author_meta.get("name"),
                author_login=author_user.get("login"),
                authored_at=author_meta.get("date"),
                html_url=item["html_url"],
            )
        )

    return RepositoryCommitsResponse(
        owner=owner,
        repo=repo,
        sha=sha,
        page=page,
        per_page=per_page,
        count=len(commits),
        commits=commits,
        provenance=_to_provenance(result),
    )
