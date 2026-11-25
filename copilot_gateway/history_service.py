"""History service: persists and retrieves genuine scan records from SQLite."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select

from .database import ChatSession, ScanRecord, ToolCallAuditRecord, get_session, now_iso
from .schemas import HistoryRecord, ToolCallTrace


class HistoryService:
    """CRUD operations on genuine persisted records. Never seeds or fabricates data."""

    def create_scan(self, owner: str, repo: str) -> int:
        with get_session() as session:
            record = ScanRecord(
                owner=owner,
                repo=repo,
                started_at=now_iso(),
                status="running",
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record.id

    def complete_scan(
        self,
        scan_id: int,
        status: str,
        total_dependencies: int = 0,
        resolved_count: int = 0,
        unresolved_count: int = 0,
        vulnerable_packages_count: int = 0,
        total_vulnerabilities: int = 0,
        scan_summary: dict[str, Any] | None = None,
        error_message: str | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        with get_session() as session:
            record = session.get(ScanRecord, scan_id)
            if record:
                record.completed_at = now_iso()
                record.status = status
                record.total_dependencies = total_dependencies
                record.resolved_count = resolved_count
                record.unresolved_count = unresolved_count
                record.vulnerable_packages_count = vulnerable_packages_count
                record.total_vulnerabilities = total_vulnerabilities
                record.scan_summary = scan_summary
                record.error_message = error_message
                record.duration_seconds = duration_seconds
                session.commit()

    def log_tool_call(
        self,
        session_id: str,
        scan_id: int | None,
        trace: ToolCallTrace,
    ) -> None:
        with get_session() as session:
            audit = ToolCallAuditRecord(
                session_id=session_id,
                scan_id=scan_id,
                server_name=trace.server_name,
                tool_name=trace.tool_name,
                arguments_json=json.dumps(trace.arguments),
                success=trace.success,
                result_summary=trace.result_summary,
                error_message=trace.error_message,
                duration_ms=trace.duration_ms,
                called_at=trace.called_at,
                source_url=trace.source_url,
            )
            session.add(audit)
            session.commit()

    def save_chat_session(
        self,
        session_id: str,
        scan_id: int | None,
        owner: str | None,
        repo: str | None,
        user_message: str,
        agent_response: str | None,
        groq_model: str | None,
        gemini_model: str | None,
        tool_calls_count: int,
        iterations: int,
        total_duration_ms: float | None,
        status: str,
        execution_trace_json: str | None,
        started_at: str,
    ) -> None:
        with get_session() as session:
            existing = session.execute(
                select(ChatSession).where(ChatSession.session_id == session_id)
            ).scalar_one_or_none()

            if existing is None:
                record = ChatSession(
                    session_id=session_id,
                    scan_id=scan_id,
                    owner=owner,
                    repo=repo,
                    user_message=user_message,
                    agent_response=agent_response,
                    groq_model_used=groq_model,
                    gemini_model_used=gemini_model,
                    tool_calls_count=tool_calls_count,
                    iterations=iterations,
                    total_duration_ms=total_duration_ms,
                    started_at=started_at,
                    completed_at=now_iso(),
                    status=status,
                    execution_trace_json=execution_trace_json,
                )
                session.add(record)
            else:
                existing.agent_response = agent_response
                existing.groq_model_used = groq_model
                existing.gemini_model_used = gemini_model
                existing.tool_calls_count = tool_calls_count
                existing.iterations = iterations
                existing.total_duration_ms = total_duration_ms
                existing.completed_at = now_iso()
                existing.status = status
                existing.execution_trace_json = execution_trace_json

            session.commit()

    def list_scans(self, limit: int = 50) -> list[HistoryRecord]:
        with get_session() as session:
            rows = (
                session.execute(
                    select(ScanRecord).order_by(ScanRecord.id.desc()).limit(limit)
                )
                .scalars()
                .all()
            )
            records: list[HistoryRecord] = []
            for row in rows:
                summary = row.scan_summary or {}
                vulns = summary.get("vulnerabilities") or []
                critical_count = sum(
                    1
                    for v in vulns
                    if str(v.get("severity") or "").upper() == "CRITICAL"
                )
                records.append(
                    HistoryRecord(
                        id=row.id,
                        owner=row.owner,
                        repo=row.repo,
                        started_at=row.started_at,
                        scanned_at=row.completed_at or row.started_at,
                        completed_at=row.completed_at,
                        duration_seconds=row.duration_seconds,
                        status=row.status,
                        total_dependencies=row.total_dependencies,
                        resolved_count=row.resolved_count,
                        unresolved_count=row.unresolved_count,
                        vulnerable_packages_count=row.vulnerable_packages_count,
                        total_vulnerabilities=row.total_vulnerabilities,
                        vulnerability_count=row.total_vulnerabilities,
                        critical=critical_count,
                        error_message=row.error_message,
                    )
                )
            return records

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with get_session() as session:
            record = session.get(ScanRecord, scan_id)
            if not record:
                return None
            return {
                "id": record.id,
                "scan_id": record.id,
                "owner": record.owner,
                "repo": record.repo,
                "started_at": record.started_at,
                "scanned_at": record.completed_at or record.started_at,
                "completed_at": record.completed_at,
                "status": record.status,
                "total_dependencies": record.total_dependencies,
                "resolved_count": record.resolved_count,
                "unresolved_count": record.unresolved_count,
                "vulnerable_packages_count": record.vulnerable_packages_count,
                "total_vulnerabilities": record.total_vulnerabilities,
                "scan_summary": record.scan_summary,
                "error_message": record.error_message,
                "duration_seconds": record.duration_seconds,
            }

    def total_scan_count(self) -> int:
        with get_session() as session:
            result = session.execute(select(func.count(ScanRecord.id))).scalar()
            return int(result or 0)

    def total_tool_call_count(self) -> int:
        with get_session() as session:
            result = session.execute(
                select(func.count(ToolCallAuditRecord.id))
            ).scalar()
            return int(result or 0)
