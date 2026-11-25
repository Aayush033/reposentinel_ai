"""FastAPI application for the copilot_gateway (port 8000)."""

from __future__ import annotations

import json
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .agent_orchestrator import run_agent, run_commit_check, run_full_scan
from .database import create_tables
from .gemini_provider import is_gemini_available
from .groq_provider import is_groq_available
from .history_service import HistoryService
from .mcp_client import get_mcp_client
from .schemas import (
    ChatRequest,
    ChatResponse,
    CommitCheckRequest,
    CommitCheckResponse,
    DiscoveredTool,
    HealthResponse,
    HistoryRecord,
    LiveStateResponse,
    MCPToolsResponse,
    ScanRequest,
    ScanResponse,
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
    mcp = get_mcp_client()
    try:
        await mcp.refresh_tools()
    except Exception as _exc:  # noqa: BLE001
        import logging as _log

        _log.getLogger(__name__).warning("MCP tool refresh failed at startup: %s", _exc)
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
async def run_scan(request: ScanRequest) -> ScanResponse:
    started_at = datetime.now(UTC).isoformat()
    scan_id = history.create_scan(request.owner.strip(), request.repo.strip())
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
        )

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


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/static/index.html")
