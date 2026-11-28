"""History service: persists and retrieves genuine scan records from SQLite."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import func, select

from .database import ChatSession, ScanRecord, ToolCallAuditRecord, get_session, now_iso
from .schemas import HistoryRecord, ToolCallTrace


class HistoryService:
    """CRUD operations on genuine persisted records. Never seeds or fabricates data."""

    def create_scan(self, owner: str, repo: str, user_id: int | None = None) -> int:
        with get_session() as session:
            record = ScanRecord(
                user_id=user_id,
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
        manifest_file: str | None = None,
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
                record.manifest_file = manifest_file

                # Compute exact severity buckets
                c_cnt, h_cnt, m_cnt, l_cnt = 0, 0, 0, 0
                if scan_summary:
                    vuln_list = scan_summary.get("vulnerabilities") or []
                    for v in vuln_list:
                        # May be a wrapper dict with list of vulnerabilities
                        sub_vulns = v.get("vulnerabilities") or [v]
                        for sv in sub_vulns:
                            sev = str(
                                sv.get("severity_label") or sv.get("severity") or ""
                            ).upper()
                            if "CRIT" in sev:
                                c_cnt += 1
                            elif "HIGH" in sev:
                                h_cnt += 1
                            elif "MED" in sev or "MOD" in sev:
                                m_cnt += 1
                            elif "LOW" in sev:
                                l_cnt += 1
                record.critical_count = c_cnt
                record.high_count = h_cnt
                record.medium_count = m_cnt
                record.low_count = l_cnt

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

    def list_scans(
        self, limit: int = 50, user_id: int | None = None
    ) -> list[HistoryRecord]:
        with get_session() as session:
            stmt = select(ScanRecord)
            if user_id is not None:
                stmt = stmt.where(ScanRecord.user_id == user_id)
            stmt = stmt.order_by(ScanRecord.id.desc()).limit(limit)
            rows = session.execute(stmt).scalars().all()
            records: list[HistoryRecord] = []
            for row in rows:
                critical_count = (
                    row.critical_count if row.critical_count is not None else 0
                )
                if critical_count == 0 and row.scan_summary:
                    vulns = row.scan_summary.get("vulnerabilities") or []
                    critical_count = sum(
                        1
                        for v in vulns
                        if "CRIT"
                        in str(
                            v.get("severity") or v.get("severity_label") or ""
                        ).upper()
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

    def get_dashboard_overview(self, user_id: int | None = None) -> dict[str, Any]:
        """Aggregate actual scan records and onboarded projects for the Moole dashboard."""
        from .database import ProjectRecord

        with get_session() as session:
            # Get user's projects or all projects if unauthenticated
            p_stmt = select(ProjectRecord)
            if user_id is not None:
                p_stmt = p_stmt.where(ProjectRecord.user_id == user_id)
            projects = session.execute(p_stmt).scalars().all()

            # Latest scan per repository
            s_stmt = select(ScanRecord)
            if user_id is not None:
                s_stmt = s_stmt.where(ScanRecord.user_id == user_id)
            scans = (
                session.execute(s_stmt.order_by(ScanRecord.id.desc())).scalars().all()
            )

            # Group scans by owner/repo to take the latest scan
            latest_by_repo: dict[str, ScanRecord] = {}
            for s in scans:
                key = f"{s.owner}/{s.repo}"
                if key not in latest_by_repo and s.status == "completed":
                    latest_by_repo[key] = s

            # Calculate metrics
            crit_tot, high_tot, med_tot, low_tot, vulns_tot = 0, 0, 0, 0, 0
            repo_rows: list[dict[str, Any]] = []

            # If user has projects, base table on projects; otherwise on latest scans
            tracked_repos = set()
            for p in projects:
                key = f"{p.owner}/{p.repo}"
                tracked_repos.add(key)
                s = latest_by_repo.get(key)
                crit = s.critical_count if s else 0
                high = s.high_count if s else 0
                med = s.medium_count if s else 0
                low = s.low_count if s else 0
                total_v = s.total_vulnerabilities if s else 0

                crit_tot += crit
                high_tot += high
                med_tot += med
                low_tot += low
                vulns_tot += total_v

                build_file = (
                    (s.manifest_file if s and s.manifest_file else None)
                    or p.primary_manifest
                    or "requirements.txt"
                )
                repo_rows.append(
                    {
                        "id": p.id,
                        "owner": p.owner,
                        "repo": p.repo,
                        "repository": f"{p.owner}/{p.repo}",
                        "critical": crit,
                        "high": high,
                        "medium": med,
                        "low": low,
                        "build_file": build_file,
                        "integration": "GitHub",
                        "last_scan": s.completed_at if s else None,
                        "last_scan_id": s.id if s else None,
                    }
                )

            # Also include any scans not yet formally onboarded as projects
            for key, s in latest_by_repo.items():
                if key not in tracked_repos:
                    crit_tot += s.critical_count or 0
                    high_tot += s.high_count or 0
                    med_tot += s.medium_count or 0
                    low_tot += s.low_count or 0
                    vulns_tot += s.total_vulnerabilities or 0
                    repo_rows.append(
                        {
                            "id": s.id,
                            "owner": s.owner,
                            "repo": s.repo,
                            "repository": f"{s.owner}/{s.repo}",
                            "critical": s.critical_count or 0,
                            "high": s.high_count or 0,
                            "medium": s.medium_count or 0,
                            "low": s.low_count or 0,
                            "build_file": s.manifest_file or "requirements.txt",
                            "integration": "GitHub",
                            "last_scan": s.completed_at,
                            "last_scan_id": s.id,
                        }
                    )

            total_onboarded = len(projects) if projects else len(repo_rows)

            return {
                "total_onboarded_repositories": total_onboarded,
                "critical_total": crit_tot,
                "high_total": high_tot,
                "medium_total": med_tot,
                "low_total": low_tot,
                "total_vulnerabilities": vulns_tot,
                "repositories": repo_rows,
            }

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
