"""Pydantic schemas for the copilot_gateway FastAPI application."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    owner: str = Field(..., min_length=1, description="GitHub repository owner")
    repo: str = Field(..., min_length=1, description="GitHub repository name")


class ToolCallTrace(BaseModel):
    server_name: str
    server: str | None = None
    tool_name: str
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    args: dict[str, Any] = Field(default_factory=dict)
    success: bool
    result_summary: str | None = None
    error_message: str | None = None
    duration_ms: float | None = None
    called_at: str
    source_url: str | None = None


class ScanResponse(BaseModel):
    scan_id: int
    owner: str
    repo: str
    status: str
    started_at: str
    scanned_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    total_dependencies: int = 0
    resolved_count: int = 0
    unresolved_count: int = 0
    vulnerable_packages_count: int = 0
    total_vulnerabilities: int = 0
    open_remediation_prs: int = 0
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    github: dict[str, Any] = Field(default_factory=dict)
    scan_summary: dict[str, Any] | None = None
    tool_calls: list[ToolCallTrace] = Field(default_factory=list)
    trace: list[ToolCallTrace] = Field(default_factory=list)
    error_message: str | None = None


class DiscoveredTool(BaseModel):
    server_name: str
    server: str | None = None
    tool_name: str
    name: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)


class MCPToolsResponse(BaseModel):
    github_server_status: str
    osv_server_status: str
    tools: list[DiscoveredTool]
    total_tools: int
    last_refreshed_at: str | None = None
    discovery_note: str | None = None


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    owner: str | None = Field(
        default=None, description="GitHub owner context for the conversation"
    )
    repo: str | None = Field(
        default=None, description="GitHub repo context for the conversation"
    )
    scan_id: int | None = None


class EvidenceSource(BaseModel):
    type: str
    id: str | None = None
    title: str | None = None
    url: str | None = None
    fetched_at: str | None = None
    source_system: str | None = None


class ChatResponse(BaseModel):
    session_id: str
    response: str
    sources: list[EvidenceSource] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)
    github_issue_refs: list[str] = Field(default_factory=list)
    github_pr_refs: list[str] = Field(default_factory=list)
    execution_trace: list[ToolCallTrace] = Field(default_factory=list)
    trace: list[ToolCallTrace] = Field(default_factory=list)
    groq_model_used: str | None = None
    gemini_model_used: str | None = None
    model_used: str | None = None
    total_tool_calls: int = 0
    iterations: int = 0
    total_duration_ms: float | None = None
    status: str = "completed"
    error_message: str | None = None


class HistoryRecord(BaseModel):
    id: int
    owner: str
    repo: str
    started_at: str
    scanned_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    status: str
    total_dependencies: int
    resolved_count: int = 0
    unresolved_count: int = 0
    vulnerable_packages_count: int
    total_vulnerabilities: int
    vulnerability_count: int = 0
    critical: int = 0
    error_message: str | None = None


class LiveStateResponse(BaseModel):
    gateway_status: str
    github_service_status: str
    osv_service_status: str
    github_mcp_server_status: str
    osv_mcp_server_status: str
    services: dict[str, dict[str, Any]] = Field(default_factory=dict)
    total_scans: int
    total_tool_calls: int
    mcp_tools_discovered: int
    registry_extension_active: bool
    groq_configured: bool
    gemini_configured: bool
    tavily_configured: bool
    github_token_configured: bool
    uptime_seconds: float
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    service: str = "copilot_gateway"
    port: int
    github_service_reachable: bool
    osv_service_reachable: bool
    github_mcp_server_status: str
    osv_mcp_server_status: str
    database_path: str
    scan_count: int
    groq_configured: bool
    gemini_configured: bool
    tavily_configured: bool
    timestamp: str


class CommitCheckRequest(BaseModel):
    owner: str | None = Field(default=None, description="GitHub repository owner")
    repo: str | None = Field(default=None, description="GitHub repository name")
    commit: str | None = Field(
        default=None,
        description="Optional full 40/64-char Git commit SHA; if omitted, latest commit is fetched via GitHub MCP",
    )


class CommitCheckResponse(BaseModel):
    commit_hash: str
    commit_url: str | None = None
    commit_message: str | None = None
    author: str | None = None
    authored_at: str | None = None
    vulnerability_count: int = 0
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    source: str
    source_url: str
    fetched_at: str
    http_status: int
    cached: bool = False
    data_freshness: str
    execution_trace: list[ToolCallTrace] = Field(default_factory=list)
    trace: list[ToolCallTrace] = Field(default_factory=list)
    note: str | None = None
