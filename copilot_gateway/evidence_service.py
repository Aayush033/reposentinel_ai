"""Evidence service: collects and structures cross-system evidence from MCP tool results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .schemas import EvidenceSource, ToolCallTrace

_SECRET_KEYS = frozenset(
    {"token", "api_key", "apikey", "secret", "password", "auth", "authorization"}
)


def _sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
    return {
        k: "***" if any(sk in k.lower() for sk in _SECRET_KEYS) else v
        for k, v in args.items()
    }


def _extract_source_url(result: dict[str, Any]) -> str | None:
    actual = result.get("result", result)
    if isinstance(actual, dict):
        for key in ("source_url", "osv_url", "html_url"):
            val = actual.get(key)
            if isinstance(val, str) and val.startswith("http"):
                return val
        prov = actual.get("provenance")
        if isinstance(prov, dict):
            url = prov.get("source_url")
            if isinstance(url, str) and url.startswith("http"):
                return url
    return None


def _summarize_result(result: dict[str, Any], tool_name: str) -> str:
    if result.get("error"):
        return f"Error: {str(result['error'])[:200]}"
    actual = result.get("result", result)
    if not isinstance(actual, dict):
        return str(actual)[:200]
    if actual.get("error"):
        return f"Error: {str(actual['error'])[:200]}"

    if "total_dependencies" in actual:
        return (
            f"{actual['total_dependencies']} deps "
            f"({actual.get('resolved_count', 0)} resolved, {actual.get('unresolved_count', 0)} unresolved)"
        )
    if "total_vulnerabilities_found" in actual:
        return (
            f"{actual['total_vulnerabilities_found']} vulns in "
            f"{actual.get('vulnerable_packages_count', 0)} packages"
        )
    if "vulnerability_id" in actual:
        return f"Advisory: {actual['vulnerability_id']} — {str(actual.get('summary') or '')[:100]}"
    if "count" in actual and "issues" in actual:
        return f"{actual['count']} issues"
    if "count" in actual and "pull_requests" in actual:
        return f"{actual['count']} pull requests"
    if "full_name" in actual:
        return f"Repo: {actual['full_name']}"
    if "latest_version" in actual:
        return f"PyPI latest: {actual.get('package_name')} {actual['latest_version']}"
    return str(actual)[:200]


def _infer_source_system(url: str) -> str:
    if "api.github.com" in url or "github.com" in url:
        return "github.com"
    if "api.osv.dev" in url or "osv.dev" in url:
        return "osv.dev"
    if "pypi.org" in url:
        return "pypi.org"
    if "tavily" in url:
        return "tavily.com"
    return "external"


class EvidenceCollector:
    """Accumulates evidence from MCP tool calls during a single agent session."""

    def __init__(self) -> None:
        self.sources: list[EvidenceSource] = []
        self.vulnerability_ids: set[str] = set()
        self.github_issue_refs: set[str] = set()
        self.github_pr_refs: set[str] = set()
        self.tool_calls: list[ToolCallTrace] = []

    def record_tool_call(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        duration_ms: float | None = None,
        called_at: str | None = None,
    ) -> ToolCallTrace:
        """Record a completed tool call and extract evidence from the result."""
        actual_data = result.get("result", result)
        nested_err = actual_data.get("error") if isinstance(actual_data, dict) else None
        success = (
            bool(result.get("success", True))
            and not result.get("error")
            and not nested_err
            and not result.get("is_error")
        )
        error_msg = result.get("error") or nested_err if not success else None

        sanitized_args = _sanitize_args(arguments)
        source_url = _extract_source_url(result)

        trace = ToolCallTrace(
            server_name=server_name,
            server=server_name,
            tool_name=tool_name,
            tool=tool_name,
            arguments=sanitized_args,
            args=sanitized_args,
            success=success,
            result_summary=_summarize_result(result, tool_name),
            error_message=str(error_msg) if error_msg else None,
            duration_ms=duration_ms,
            called_at=called_at or datetime.now(UTC).isoformat(),
            source_url=source_url,
        )
        self.tool_calls.append(trace)

        if isinstance(actual_data, dict) and success:
            self._extract_evidence(tool_name, actual_data, source_url)

        return trace

    def _extract_evidence(
        self, tool_name: str, data: dict[str, Any], source_url: str | None
    ) -> None:
        if "results" in data and isinstance(data["results"], list):
            for item in data["results"]:
                if not isinstance(item, dict):
                    continue
                for vid in item.get("vulnerability_ids") or []:
                    self.vulnerability_ids.add(str(vid))
                for vuln in item.get("vulnerabilities") or []:
                    if isinstance(vuln, dict) and vuln.get("vulnerability_id"):
                        self.vulnerability_ids.add(str(vuln["vulnerability_id"]))
                        self.sources.append(
                            EvidenceSource(
                                type="osv_vulnerability",
                                id=vuln["vulnerability_id"],
                                title=vuln.get("summary"),
                                url=vuln.get("osv_url"),
                                fetched_at=(vuln.get("provenance") or {}).get(
                                    "fetched_at"
                                ),
                                source_system="osv.dev",
                            )
                        )

        if "issues" in data and isinstance(data["issues"], list):
            for issue in data["issues"]:
                if isinstance(issue, dict):
                    url = issue.get("html_url", "")
                    if url:
                        self.github_issue_refs.add(url)
                    self.sources.append(
                        EvidenceSource(
                            type="github_issue",
                            id=str(issue.get("number", "")),
                            title=issue.get("title"),
                            url=url or None,
                            source_system="github.com",
                        )
                    )

        if "pull_requests" in data and isinstance(data["pull_requests"], list):
            for pr in data["pull_requests"]:
                if isinstance(pr, dict):
                    url = pr.get("html_url", "")
                    if url:
                        self.github_pr_refs.add(url)
                    self.sources.append(
                        EvidenceSource(
                            type="github_pull_request",
                            id=str(pr.get("number", "")),
                            title=pr.get("title"),
                            url=url or None,
                            source_system="github.com",
                        )
                    )

        if "vulnerability_id" in data:
            self.vulnerability_ids.add(str(data["vulnerability_id"]))
            if data.get("osv_url"):
                self.sources.append(
                    EvidenceSource(
                        type="osv_vulnerability",
                        id=data["vulnerability_id"],
                        title=data.get("summary"),
                        url=data.get("osv_url"),
                        source_system="osv.dev",
                    )
                )

        if "latest_version" in data and data.get("source_url"):
            self.sources.append(
                EvidenceSource(
                    type="pypi_registry",
                    id=data.get("package_name"),
                    title=f"Latest PyPI release: {data.get('latest_version')}",
                    url=data.get("source_url"),
                    fetched_at=data.get("fetched_at"),
                    source_system="pypi.org",
                )
            )

        if "commit_hash" in data and isinstance(data.get("vulnerabilities"), list):
            for vuln in data["vulnerabilities"]:
                if isinstance(vuln, dict) and vuln.get("vulnerability_id"):
                    self.vulnerability_ids.add(str(vuln["vulnerability_id"]))
                    self.sources.append(
                        EvidenceSource(
                            type="osv_commit_vulnerability",
                            id=vuln["vulnerability_id"],
                            title=vuln.get("summary"),
                            url=vuln.get("osv_url") or data.get("source_url"),
                            fetched_at=data.get("fetched_at"),
                            source_system="osv.dev",
                        )
                    )

        if "commits" in data and isinstance(data["commits"], list):
            for commit in data["commits"][:3]:
                if isinstance(commit, dict) and commit.get("html_url"):
                    self.sources.append(
                        EvidenceSource(
                            type="github_commit",
                            id=commit.get("short_sha") or commit.get("sha"),
                            title=commit.get("message"),
                            url=commit.get("html_url"),
                            source_system="github.com",
                        )
                    )

        if source_url:
            self.sources.append(
                EvidenceSource(
                    type="api_response",
                    url=source_url,
                    source_system=_infer_source_system(source_url),
                )
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": [s.model_dump() for s in self.sources],
            "vulnerability_ids": sorted(self.vulnerability_ids),
            "github_issue_refs": sorted(self.github_issue_refs),
            "github_pr_refs": sorted(self.github_pr_refs),
            "tool_calls": [t.model_dump() for t in self.tool_calls],
        }
