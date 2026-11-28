"""FastAPI application for the copilot_gateway (port 8000)."""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .agent_orchestrator import run_agent, run_commit_check, run_full_scan
from .auth import (
    check_rate_limit,
    clear_failed_logins,
    clear_session_cookie,
    create_user_session,
    get_current_user,
    get_current_user_optional,
    get_token_from_request,
    hash_password,
    record_failed_login,
    revoke_session,
    set_session_cookie,
    verify_password,
)
from .database import ProjectRecord, UserRecord, create_tables, get_session, now_iso
from .gemini_provider import is_gemini_available
from .groq_provider import is_groq_available
from .history_service import HistoryService
from .mcp_client import get_mcp_client
from .schemas import (
    ChatRequest,
    ChatResponse,
    CommitCheckRequest,
    CommitCheckResponse,
    DashboardOverviewResponse,
    DiscoveredTool,
    HealthResponse,
    HistoryRecord,
    LiveStateResponse,
    LoginRequest,
    MCPToolsResponse,
    ProjectCreateRequest,
    ProjectListResponse,
    ProjectResponse,
    RegisterRequest,
    ScanRequest,
    ScanResponse,
    UserResponse,
)
from .tavily_provider import is_tavily_available

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

_STARTUP_TIME = time.monotonic()
_GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))
_GITHUB_SVC_URL = os.getenv("GITHUB_SERVICE_URL", "http://127.0.0.1:8001")
_OSV_SVC_URL = os.getenv("OSV_SERVICE_URL", "http://127.0.0.1:8002")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    if not os.getenv("PYTEST_CURRENT_TEST") and not os.getenv("SKIP_MCP_STARTUP"):
        mcp = get_mcp_client()
        try:
            await mcp.refresh_tools()
        except Exception as _exc:  # noqa: BLE001
            import logging as _log

            _log.getLogger(__name__).warning(
                "MCP tool refresh failed at startup: %s", _exc
            )
    yield


app = FastAPI(
    title="RepoSentinel AI — Copilot Gateway",
    description="Cross-system security copilot: GitHub x OSV.dev, powered by Synapse MCP + Groq + Gemini.",
    version="1.0.0",
    lifespan=lifespan,
)

_STATIC_DIR = Path(__file__).parent / "static"
_STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

history = HistoryService()


async def _check_service(url: str, timeout: float = 5.0) -> bool:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{url}/health")
            return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def _serialize_tools(mcp) -> list[DiscoveredTool]:
    return [
        DiscoveredTool(
            server_name=info.server_name,
            server=info.server_name,
            tool_name=info.tool.name,
            name=info.tool.name,
            description=info.tool.description,
            input_schema=info.tool.input_schema
            if isinstance(getattr(info.tool, "input_schema", None), dict)
            else {},
        )
        for info in mcp.tool_registry.values()
    ]


@app.get("/health", response_model=HealthResponse, summary="Gateway health check")
async def health_check() -> HealthResponse:
    mcp = get_mcp_client()
    gh_ok = await _check_service(_GITHUB_SVC_URL)
    osv_ok = await _check_service(_OSV_SVC_URL)
    db_path = str(Path(__file__).parent / "reposentinel.db")
    return HealthResponse(
        status="ok",
        port=_GATEWAY_PORT,
        github_service_reachable=gh_ok,
        osv_service_reachable=osv_ok,
        github_mcp_server_status=mcp.github_status.status,
        osv_mcp_server_status=mcp.osv_status.status,
        database_path=db_path,
        scan_count=history.total_scan_count(),
        groq_configured=is_groq_available(),
        gemini_configured=is_gemini_available(),
        tavily_configured=is_tavily_available(),
        timestamp=datetime.now(UTC).isoformat(),
    )


@app.get(
    "/api/mcp-tools",
    response_model=MCPToolsResponse,
    summary="Return actually discovered MCP tools",
)
async def get_mcp_tools() -> MCPToolsResponse:
    mcp = get_mcp_client()
    tools = _serialize_tools(mcp)
    return MCPToolsResponse(
        github_server_status=mcp.github_status.status,
        osv_server_status=mcp.osv_status.status,
        tools=tools,
        total_tools=len(tools),
        last_refreshed_at=mcp.last_refreshed_at,
        discovery_note="Tools are discovered dynamically via list_tools() from both Synapse MCP servers.",
    )


@app.post(
    "/api/refresh-tools",
    response_model=MCPToolsResponse,
    summary="Reconnect MCP sessions and rediscover tools",
)
async def refresh_mcp_tools() -> MCPToolsResponse:
    mcp = get_mcp_client()
    await mcp.refresh_tools()
    tools = _serialize_tools(mcp)
    return MCPToolsResponse(
        github_server_status=mcp.github_status.status,
        osv_server_status=mcp.osv_status.status,
        tools=tools,
        total_tools=len(tools),
        last_refreshed_at=mcp.last_refreshed_at,
        discovery_note=f"Refreshed at {mcp.last_refreshed_at}. GitHub: {mcp.github_status.status}, OSV: {mcp.osv_status.status}.",
    )


@app.post(
    "/api/scan",
    response_model=ScanResponse,
    summary="Run a cross-system security scan via MCP",
)
async def run_scan(
    request: ScanRequest,
    current_user: UserRecord | None = Depends(get_current_user_optional),  # noqa: B008
) -> ScanResponse:
    started_at = datetime.now(UTC).isoformat()
    user_id = current_user.id if current_user else None
    scan_id = history.create_scan(
        request.owner.strip(), request.repo.strip(), user_id=user_id
    )
    start_ns = time.monotonic_ns()
    mcp = get_mcp_client()

    try:
        scan_result = await run_full_scan(
            request.owner.strip(), request.repo.strip(), mcp_client=mcp
        )
        duration_s = round((time.monotonic_ns() - start_ns) / 1_000_000_000, 2)
        completed_at = datetime.now(UTC).isoformat()

        traces = scan_result["execution_trace"]
        audit_session_id = f"scan-{scan_id}"
        for trace in traces:
            history.log_tool_call(
                session_id=audit_session_id,
                scan_id=scan_id,
                trace=trace,
            )

        summary_payload = {
            "vulnerability_ids": scan_result["vulnerability_ids"],
            "manifests_found": scan_result["manifests_found"],
            "dependencies": scan_result["dependencies"],
            "vulnerabilities": scan_result["vulnerabilities"],
            "github": scan_result["github"],
            "open_remediation_prs": scan_result["open_remediation_prs"],
        }

        primary_manifest = (
            scan_result["manifests_found"][0]
            if scan_result["manifests_found"]
            else None
        )

        history.complete_scan(
            scan_id=scan_id,
            status="completed",
            total_dependencies=scan_result["total_dependencies"],
            resolved_count=scan_result["resolved_count"],
            unresolved_count=scan_result["unresolved_count"],
            vulnerable_packages_count=scan_result["vulnerable_packages_count"],
            total_vulnerabilities=scan_result["total_vulnerabilities"],
            scan_summary=summary_payload,
            duration_seconds=duration_s,
            manifest_file=primary_manifest,
        )

        # Update project last scanned time if tracked
        if user_id is not None:
            with get_session() as db:
                p = db.scalar(
                    select(ProjectRecord).where(
                        ProjectRecord.user_id == user_id,
                        ProjectRecord.owner == request.owner.strip(),
                        ProjectRecord.repo == request.repo.strip(),
                    )
                )
                if p:
                    p.last_scanned_at = completed_at
                    if primary_manifest:
                        p.primary_manifest = primary_manifest
                    db.commit()

        return ScanResponse(
            scan_id=scan_id,
            owner=scan_result["owner"],
            repo=scan_result["repo"],
            status="completed",
            started_at=started_at,
            scanned_at=completed_at,
            completed_at=completed_at,
            duration_seconds=duration_s,
            total_dependencies=scan_result["total_dependencies"],
            resolved_count=scan_result["resolved_count"],
            unresolved_count=scan_result["unresolved_count"],
            vulnerable_packages_count=scan_result["vulnerable_packages_count"],
            total_vulnerabilities=scan_result["total_vulnerabilities"],
            open_remediation_prs=scan_result["open_remediation_prs"],
            dependencies=scan_result["dependencies"],
            vulnerabilities=scan_result["vulnerabilities"],
            github=scan_result["github"],
            scan_summary=summary_payload,
            tool_calls=traces,
            trace=traces,
        )

    except Exception as exc:
        duration_s = round((time.monotonic_ns() - start_ns) / 1_000_000_000, 2)
        err_msg = str(exc)
        history.complete_scan(
            scan_id=scan_id,
            status="error",
            error_message=err_msg,
            duration_seconds=duration_s,
        )
        raise HTTPException(
            status_code=502, detail={"error": err_msg, "scan_id": scan_id}
        ) from exc


@app.post(
    "/api/chat",
    response_model=ChatResponse,
    summary="Run the AI agent for a chat message",
)
async def chat(request: ChatRequest) -> ChatResponse:
    if not is_groq_available():
        raise HTTPException(
            status_code=503,
            detail="GROQ_API_KEY is not configured. Add GROQ_API_KEY to .env to run the AI agent.",
        )

    mcp = get_mcp_client()
    if not mcp.tool_registry:
        await mcp.refresh_tools()

    started_at = datetime.now(UTC).isoformat()
    response = await run_agent(
        user_message=request.message,
        owner=request.owner,
        repo=request.repo,
        scan_id=request.scan_id,
        mcp_client=mcp,
    )

    for trace in response.execution_trace:
        history.log_tool_call(
            session_id=response.session_id,
            scan_id=request.scan_id,
            trace=trace,
        )

    history.save_chat_session(
        session_id=response.session_id,
        scan_id=request.scan_id,
        owner=request.owner,
        repo=request.repo,
        user_message=request.message,
        agent_response=response.response,
        groq_model=response.groq_model_used,
        gemini_model=response.gemini_model_used,
        tool_calls_count=response.total_tool_calls,
        iterations=response.iterations,
        total_duration_ms=response.total_duration_ms,
        status=response.status,
        execution_trace_json=json.dumps(
            [t.model_dump() for t in response.execution_trace]
        ),
        started_at=started_at,
    )

    return response


@app.post(
    "/api/commit-check",
    response_model=CommitCheckResponse,
    summary="Check a GitHub latest commit or exact commit SHA against OSV via MCP",
)
async def commit_check(request: CommitCheckRequest) -> CommitCheckResponse:
    mcp = get_mcp_client()
    try:
        res = await run_commit_check(
            owner=request.owner.strip() if request.owner else None,
            repo=request.repo.strip() if request.repo else None,
            commit=request.commit.strip() if request.commit else None,
            mcp_client=mcp,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc)}) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": str(exc)}) from exc

    traces = res["execution_trace"]
    for trace in traces:
        history.log_tool_call(
            session_id=f"commit-{res['commit_hash'][:12]}",
            scan_id=None,
            trace=trace,
        )

    return CommitCheckResponse(
        commit_hash=res["commit_hash"],
        commit_url=res["commit_url"],
        commit_message=res["commit_message"],
        author=res["author"],
        authored_at=res["authored_at"],
        vulnerability_count=res["vulnerability_count"],
        vulnerabilities=res["vulnerabilities"],
        source=res["source"],
        source_url=res["source_url"],
        fetched_at=res["fetched_at"],
        http_status=res["http_status"],
        cached=res["cached"],
        data_freshness=res["data_freshness"],
        execution_trace=traces,
        trace=traces,
        note=res.get("note"),
    )


@app.get(
    "/api/history",
    response_model=list[HistoryRecord],
    summary="Return genuine persisted scan history",
)
async def get_history() -> list[HistoryRecord]:
    return history.list_scans(limit=50)


@app.get(
    "/api/history/{scan_id}", summary="Return full persisted details for a single scan"
)
async def get_history_item(scan_id: int) -> dict:
    item = history.get_scan(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    summary = item.get("scan_summary") or {}
    return {
        **item,
        "dependencies": summary.get("dependencies", []),
        "vulnerabilities": summary.get("vulnerabilities", []),
        "github": summary.get("github", {}),
        "open_remediation_prs": summary.get("open_remediation_prs", 0),
    }


@app.get(
    "/api/live-state",
    response_model=LiveStateResponse,
    summary="Current live application state",
)
async def get_live_state() -> LiveStateResponse:
    mcp = get_mcp_client()
    gh_ok = await _check_service(_GITHUB_SVC_URL)
    osv_ok = await _check_service(_OSV_SVC_URL)

    registry_active = False
    if osv_ok:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{_OSV_SVC_URL}/health")
                if resp.status_code == 200:
                    registry_active = bool(
                        resp.json().get("registry_extension_active", False)
                    )
        except Exception:  # noqa: BLE001, S110
            pass  # registry_active stays False; non-critical OSV health probe

    groq_ok = is_groq_available()
    gemini_ok = is_gemini_available()

    services = {
        "github-service": {"status": "ok" if gh_ok else "error"},
        "osv-service": {
            "status": "ok" if osv_ok else "error",
            "registry_extension_active": registry_active,
        },
        "github-mcp": {"status": mcp.github_status.status},
        "osv-mcp": {"status": mcp.osv_status.status},
        "groq": {"status": "ok" if groq_ok else "warn"},
        "gemini": {"status": "ok" if gemini_ok else "warn"},
    }

    return LiveStateResponse(
        gateway_status="ok",
        github_service_status="ok" if gh_ok else "unreachable",
        osv_service_status="ok" if osv_ok else "unreachable",
        github_mcp_server_status=mcp.github_status.status,
        osv_mcp_server_status=mcp.osv_status.status,
        services=services,
        total_scans=history.total_scan_count(),
        total_tool_calls=history.total_tool_call_count(),
        mcp_tools_discovered=len(mcp.tool_registry),
        registry_extension_active=registry_active,
        groq_configured=groq_ok,
        gemini_configured=gemini_ok,
        tavily_configured=is_tavily_available(),
        github_token_configured=bool(os.getenv("GITHUB_TOKEN")),
        uptime_seconds=round(time.monotonic() - _STARTUP_TIME, 1),
        timestamp=datetime.now(UTC).isoformat(),
    )


# --- Authentication Endpoints ---


@app.post(
    "/api/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new local user account with Argon2id password hashing",
)
async def register_user(request: RegisterRequest, response: Response):
    username = request.username.strip().lower()
    email = request.email.strip().lower()

    with get_session() as db:
        existing = db.scalar(
            select(UserRecord).where(
                (UserRecord.username == username) | (UserRecord.email == email)
            )
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email is already registered.",
            )

        pwd_hash = hash_password(request.password)
        user = UserRecord(
            username=username,
            email=email,
            password_hash=pwd_hash,
            full_name=request.full_name.strip() if request.full_name else None,
            created_at=now_iso(),
            last_login_at=now_iso(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        user_resp = UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )

    raw_token, _ = create_user_session(user_resp.id)
    set_session_cookie(response, raw_token)
    return user_resp


@app.post(
    "/api/auth/login",
    response_model=UserResponse,
    summary="Authenticate user and issue secure HTTP-only session cookie",
)
async def login_user(
    request: LoginRequest,
    req: Request,
    response: Response,
):
    login_id = request.username_or_email.strip().lower()
    check_rate_limit(login_id)

    with get_session() as db:
        user = db.scalar(
            select(UserRecord).where(
                (UserRecord.username == login_id) | (UserRecord.email == login_id)
            )
        )
        if not user or not verify_password(request.password, user.password_hash):
            record_failed_login(login_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password.",
            )

        clear_failed_logins(login_id)
        user.last_login_at = now_iso()
        db.commit()

        user_resp = UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )

    raw_token, _ = create_user_session(
        user_resp.id,
        ip_address=req.client.host if req.client else None,
        user_agent=req.headers.get("user-agent"),
    )
    set_session_cookie(response, raw_token)
    return user_resp


@app.post(
    "/api/auth/logout",
    summary="Revoke session and clear session cookie",
)
async def logout_user(
    response: Response,
    token: str | None = Depends(get_token_from_request),
):
    if token:
        revoke_session(token)
    clear_session_cookie(response)
    return {"status": "ok", "message": "Logged out successfully."}


@app.get(
    "/api/auth/me",
    response_model=UserResponse,
    summary="Return authenticated profile for the current session",
)
async def get_current_user_profile(
    current_user: UserRecord = Depends(get_current_user),  # noqa: B008
):
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at,
    )


# --- Project Management Endpoints ---


def _parse_repo_slug(url_or_slug: str) -> tuple[str, str]:
    raw = url_or_slug.strip().rstrip("/")
    raw = re.sub(r"^https?://github\.com/", "", raw, flags=re.IGNORECASE)
    raw = raw.removesuffix(".git")
    parts = raw.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository format. Use 'owner/repo' or 'https://github.com/owner/repo'",
        )
    return parts[0], parts[1]


@app.get(
    "/api/projects",
    response_model=ProjectListResponse,
    summary="List onboarded repositories for the authenticated user",
)
async def list_projects(
    current_user: UserRecord = Depends(get_current_user),  # noqa: B008
):
    with get_session() as db:
        projects = (
            db.execute(
                select(ProjectRecord)
                .where(ProjectRecord.user_id == current_user.id)
                .order_by(ProjectRecord.id.desc())
            )
            .scalars()
            .all()
        )

        result = [
            ProjectResponse(
                id=p.id,
                owner=p.owner,
                repo=p.repo,
                default_branch=p.default_branch,
                description=p.description,
                stars=p.stars,
                forks=p.forks,
                open_issues=p.open_issues,
                primary_manifest=p.primary_manifest,
                created_at=p.created_at,
                last_scanned_at=p.last_scanned_at,
            )
            for p in projects
        ]
        return ProjectListResponse(projects=result, total_projects=len(result))


@app.post(
    "/api/projects",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Onboard a GitHub repository persistently after verifying via GitHub API",
)
async def create_project(
    request: ProjectCreateRequest,
    current_user: UserRecord = Depends(get_current_user),  # noqa: B008
):
    owner, repo = _parse_repo_slug(request.repo_url_or_slug)

    with get_session() as db:
        existing = db.scalar(
            select(ProjectRecord).where(
                ProjectRecord.user_id == current_user.id,
                ProjectRecord.owner == owner,
                ProjectRecord.repo == repo,
            )
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Repository {owner}/{repo} is already onboarded.",
            )

    # Verify repository through genuine GitHub service
    metadata: dict = {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_GITHUB_SVC_URL}/repos/{owner}/{repo}")
            if resp.status_code == 200:
                metadata = resp.json()
            elif resp.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Repository '{owner}/{repo}' was not found on GitHub.",
                )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        import logging as _log

        _log.getLogger(__name__).warning("GitHub verification probe error: %s", exc)

    with get_session() as db:
        project = ProjectRecord(
            user_id=current_user.id,
            owner=owner,
            repo=repo,
            default_branch=metadata.get("default_branch", "main"),
            description=metadata.get("description"),
            stars=metadata.get("stars", 0),
            forks=metadata.get("forks", 0),
            open_issues=metadata.get("open_issues", 0),
            primary_manifest=None,
            created_at=now_iso(),
            last_scanned_at=None,
        )
        db.add(project)
        db.commit()
        db.refresh(project)

        return ProjectResponse(
            id=project.id,
            owner=project.owner,
            repo=project.repo,
            default_branch=project.default_branch,
            description=project.description,
            stars=project.stars,
            forks=project.forks,
            open_issues=project.open_issues,
            primary_manifest=project.primary_manifest,
            created_at=project.created_at,
            last_scanned_at=project.last_scanned_at,
        )


@app.get(
    "/api/projects/{project_id}",
    response_model=ProjectResponse,
    summary="Get details of a single onboarded repository",
)
async def get_project(
    project_id: int,
    current_user: UserRecord = Depends(get_current_user),  # noqa: B008
):
    with get_session() as db:
        project = db.scalar(
            select(ProjectRecord).where(
                ProjectRecord.id == project_id,
                ProjectRecord.user_id == current_user.id,
            )
        )
        if not project:
            raise HTTPException(status_code=404, detail="Project not found.")
        return ProjectResponse(
            id=project.id,
            owner=project.owner,
            repo=project.repo,
            default_branch=project.default_branch,
            description=project.description,
            stars=project.stars,
            forks=project.forks,
            open_issues=project.open_issues,
            primary_manifest=project.primary_manifest,
            created_at=project.created_at,
            last_scanned_at=project.last_scanned_at,
        )


@app.delete(
    "/api/projects/{project_id}",
    summary="Remove an onboarded repository",
)
async def delete_project(
    project_id: int,
    current_user: UserRecord = Depends(get_current_user),  # noqa: B008
):
    with get_session() as db:
        project = db.scalar(
            select(ProjectRecord).where(
                ProjectRecord.id == project_id,
                ProjectRecord.user_id == current_user.id,
            )
        )
        if not project:
            raise HTTPException(status_code=404, detail="Project not found.")
        db.delete(project)
        db.commit()
    return {"status": "ok", "message": f"Project {project_id} removed successfully."}


# --- Moole-Inspired Dashboard Overview Endpoint ---


@app.get(
    "/api/dashboard/overview",
    response_model=DashboardOverviewResponse,
    summary="Return real vulnerability distribution and onboarded repositories for Moole layout",
)
async def get_dashboard_overview(
    current_user: UserRecord | None = Depends(get_current_user_optional),  # noqa: B008
):
    user_id = current_user.id if current_user else None
    data = history.get_dashboard_overview(user_id=user_id)
    return DashboardOverviewResponse(
        total_onboarded_repositories=data["total_onboarded_repositories"],
        selected_project=None,
        critical_total=data["critical_total"],
        high_total=data["high_total"],
        medium_total=data["medium_total"],
        low_total=data["low_total"],
        total_vulnerabilities=data["total_vulnerabilities"],
        repositories=data["repositories"],
    )


# --- HTML5 Page Navigation Routes ---


_INDEX_FILE = _STATIC_DIR / "index.html"


@app.get("/", include_in_schema=False)
@app.get("/login", include_in_schema=False)
@app.get("/register", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
@app.get("/projects", include_in_schema=False)
@app.get("/vulnerabilities", include_in_schema=False)
@app.get("/github-correlation", include_in_schema=False)
@app.get("/commit-security", include_in_schema=False)
@app.get("/copilot", include_in_schema=False)
@app.get("/mcp-inspector", include_in_schema=False)
@app.get("/activity", include_in_schema=False)
@app.get("/settings", include_in_schema=False)
async def serve_app():
    return FileResponse(str(_INDEX_FILE))
