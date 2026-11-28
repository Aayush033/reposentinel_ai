"""
Agent orchestrator: multi-step tool-calling agent and cross-system scan runner.

All repository and vulnerability data flows strictly through the two
Synapse-generated MCP servers.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from .evidence_service import EvidenceCollector
from .gemini_provider import gemini_synthesize, is_gemini_available
from .groq_provider import groq_chat_with_tools, is_groq_available
from .mcp_client import MCPClientManager, get_mcp_client
from .schemas import ChatResponse, EvidenceSource
from .tavily_provider import is_tavily_available, tavily_search_vulnerability

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)

MAX_ITERATIONS = int(os.getenv("AGENT_MAX_ITERATIONS", "12"))
TOOL_CALL_TIMEOUT = float(os.getenv("AGENT_TOOL_TIMEOUT", "60.0"))


def _build_groq_tools(mcp_client: MCPClientManager) -> list[dict[str, Any]]:
    """Convert dynamically discovered MCP tools into Groq function-calling schemas."""
    tools: list[dict[str, Any]] = []
    for tool_name, tool_info in mcp_client.tool_registry.items():
        schema = getattr(tool_info.tool, "input_schema", None) or {}
        if hasattr(schema, "model_dump"):
            schema = schema.model_dump()
        elif not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": tool_info.tool.description
                    or f"MCP tool: {tool_name}",
                    "parameters": schema,
                },
            }
        )
    return tools


def _build_system_prompt(owner: str | None, repo: str | None) -> str:
    repo_context = (
        f"{owner}/{repo}" if owner and repo else "the repository under discussion"
    )
    return f"""You are RepoSentinel AI, a security copilot for GitHub repositories.

You have access to tools discovered dynamically from two MCP servers:
- GitHub MCP server (github-service-mcp): repository metadata, dependency manifests, issues, pull requests, and commits.
- OSV MCP server (osv-service-mcp): OSV.dev batch vulnerability queries by package version, commit-hash vulnerability queries, full advisory details, and (when discovered) PyPI latest published releases.

CURRENT REPOSITORY CONTEXT: {repo_context}

CROSS-SYSTEM COMMIT & DEPENDENCY WORKFLOWS:
1. "Check whether the latest commit of this GitHub repository has known OSV vulnerabilities":
   - Call the GitHub MCP commits tool (e.g. list_repository_commits) to retrieve the actual latest commit.
   - Extract its complete 40-character SHA and GitHub commit link.
   - Pass that exact SHA to the OSV MCP commit-query tool (e.g. query_vulnerabilities_by_commit_hash).
   - Report the exact commit SHA, GitHub commit link, and OSV findings.
2. "Check this exact commit SHA against OSV":
   - Pass the user-supplied full commit SHA directly to the OSV MCP commit-query tool.
3. "Compare the repository's dependency vulnerabilities with the vulnerabilities associated with its latest commit":
   - Run the dependency manifest + OSV package-version batch scan AND the separate latest-commit OSV query.
   - Present dependency-level findings and commit-level findings separately; never mix their counts.
4. "Show the actual OSV evidence and the GitHub commit link":
   - Preserve exact OSV vulnerability IDs, OSV URLs, fixed versions (if provided), severity (if supplied), and the GitHub commit html_url.
5. If the OSV commit-query tool is unavailable in your discovered tools, state clearly that commit lookup could not be performed. Never fall back to invented data.

STRICT EVIDENCE RULES:
1. Always retrieve real data via MCP tools — never invent repository metadata, dependency versions, commit SHAs, vulnerability IDs, CVSS scores, fixed versions, issues, or PRs.
2. Only classify a package or commit as VULNERABLE when an OSV MCP tool returns a matching vulnerability record.
3. A successful OSV commit query returning zero vulnerabilities means OSV has no known vulnerability records associated with that commit. It does NOT establish that the repository is secure and does NOT replace dependency-version scanning or a source-code security audit.
4. Mark dependencies without an exact pinned version as UNRESOLVED — never claim they are safe or vulnerable.
5. Only report fixed versions explicitly provided by OSV. If OSV omits fixed versions, state that none were provided.
6. Distinguish clearly between confirmed remediation PRs (explicitly referencing the vulnerability ID) and possible matches (mentioning only the package name).
7. If any tool returns an error or unreachable status, report the exact failure honestly. Never treat an API failure as a clean scan.
8. Never assume a latest PyPI release is automatically compatible with the repository's version constraints.
"""


async def run_agent(
    user_message: str,
    owner: str | None,
    repo: str | None,
    scan_id: int | None,
    mcp_client: MCPClientManager | None = None,
) -> ChatResponse:
    """Execute a multi-step tool-calling agent loop using Groq + dynamic MCP tools, synthesized by Gemini."""
    if mcp_client is None:
        mcp_client = get_mcp_client()

    if not mcp_client.tool_registry:
        await mcp_client.refresh_tools()

    if not is_groq_available():
        return ChatResponse(
            session_id=str(uuid.uuid4()),
            response="Cannot proceed: GROQ_API_KEY is not configured. Groq is required as the agent orchestration model.",
            status="error",
            error_message="GROQ_API_KEY not set",
        )

    session_id = str(uuid.uuid4())
    evidence = EvidenceCollector()
    start_ns = time.monotonic_ns()

    groq_tools = _build_groq_tools(mcp_client)
    system_prompt = _build_system_prompt(owner, repo)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    groq_model_used: str | None = None
    iterations = 0
    final_text: str | None = None
    agent_error: str | None = None

    while iterations < MAX_ITERATIONS:
        iterations += 1

        groq_result = await groq_chat_with_tools(
            messages=messages,
            tools=groq_tools if groq_tools else None,
            tool_choice="auto" if groq_tools else None,
        )

        if not groq_result.get("success"):
            agent_error = str(groq_result.get("error", "Unknown Groq error"))
            final_text = (
                f"Agent orchestration failed at iteration {iterations}: {agent_error}. "
                "Verify GROQ_API_KEY and model availability."
            )
            break

        groq_model_used = groq_result.get("model")
        message = groq_result.get("message")
        finish_reason = groq_result.get("finish_reason")

        assistant_turn: dict[str, Any] = {
            "role": "assistant",
            "content": message.content if hasattr(message, "content") else None,
        }
        tool_calls_raw = getattr(message, "tool_calls", None) or []
        if tool_calls_raw:
            assistant_turn["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in tool_calls_raw
            ]
        messages.append(assistant_turn)

        if not tool_calls_raw:
            final_text = message.content if hasattr(message, "content") else None
            if not final_text and finish_reason == "stop":
                final_text = "The model completed without producing response text."
            break

        for tc in tool_calls_raw:
            fn_name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}

            tool_called_at = datetime.now(UTC).isoformat()
            call_result = await mcp_client.call_tool(
                fn_name, args, timeout=TOOL_CALL_TIMEOUT
            )

            info = mcp_client.tool_registry.get(fn_name)
            server_name = call_result.get("server_name") or (
                info.server_name if info else "unknown"
            )

            evidence.record_tool_call(
                server_name=server_name,
                tool_name=fn_name,
                arguments=args,
                result=call_result,
                duration_ms=call_result.get("duration_ms"),
                called_at=tool_called_at,
            )

            # Supplementary Tavily research when user specifically asks for external advisory context
            actual_result = call_result.get("result", call_result)
            wants_external_research = any(
                kw in user_message.lower()
                for kw in (
                    "advisory",
                    "tavily",
                    "external",
                    "cve",
                    "more info",
                    "background",
                    "vendor",
                )
            )
            if (
                wants_external_research
                and isinstance(actual_result, dict)
                and is_tavily_available()
            ):
                for vid in list(evidence.vulnerability_ids)[:2]:
                    if not any(
                        s.id == vid and s.type == "tavily_search"
                        for s in evidence.sources
                    ):
                        pkg = None
                        if isinstance(actual_result.get("results"), list):
                            for dep_res in actual_result["results"]:
                                if isinstance(dep_res, dict) and vid in (
                                    dep_res.get("vulnerability_ids") or []
                                ):
                                    pkg = dep_res.get("package_name")
                                    break
                        tavily_res = await tavily_search_vulnerability(vid, pkg)
                        if tavily_res.get("success") and tavily_res.get("results"):
                            for tr in tavily_res["results"][:2]:
                                evidence.sources.append(
                                    EvidenceSource(
                                        type="tavily_search",
                                        id=vid,
                                        title=tr.get("title"),
                                        url=tr.get("url"),
                                        source_system="tavily.com",
                                    )
                                )

            raw_res = call_result.get("result", call_result)
            tool_result_content = json.dumps(raw_res, default=str)
            if len(tool_result_content) > 3500:
                if isinstance(raw_res, dict):
                    compact_dict = dict(raw_res)
                    if "results" in compact_dict and isinstance(
                        compact_dict["results"], list
                    ):
                        total_r = len(compact_dict["results"])
                        compact_dict["results"] = compact_dict["results"][:10]
                        compact_dict["_notice"] = (
                            f"Showing top 10 of {total_r} items to respect LLM rate limits."
                        )
                    elif "dependencies" in compact_dict and isinstance(
                        compact_dict["dependencies"], list
                    ):
                        total_d = len(compact_dict["dependencies"])
                        compact_dict["dependencies"] = compact_dict["dependencies"][:15]
                        compact_dict["_notice"] = (
                            f"Showing first 15 of {total_d} dependencies."
                        )
                    elif "commits" in compact_dict and isinstance(
                        compact_dict["commits"], list
                    ):
                        compact_dict["commits"] = compact_dict["commits"][:5]
                    tool_result_content = json.dumps(compact_dict, default=str)
                if len(tool_result_content) > 3500:
                    tool_result_content = (
                        tool_result_content[:3500]
                        + "\n...(truncated to respect rate limits)"
                    )

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": tool_result_content,
                }
            )

    if final_text is None and not agent_error:
        final_text = f"Agent reached max iterations ({MAX_ITERATIONS}) after {len(evidence.tool_calls)} MCP tool calls."

    # Gemini synthesis pass (falls back cleanly to Groq output if Gemini fails or is unconfigured)
    gemini_model_used: str | None = None
    if not agent_error and final_text and evidence.tool_calls and is_gemini_available():
        synthesis_context = (
            f"You are synthesizing a factual security report for {owner}/{repo if owner and repo else 'the target repository'}.\n\n"
            f"Verified MCP evidence summary:\n"
            f"- Vulnerability IDs observed: {sorted(evidence.vulnerability_ids)}\n"
            f"- GitHub issue URLs observed: {sorted(evidence.github_issue_refs)[:10]}\n"
            f"- GitHub PR URLs observed: {sorted(evidence.github_pr_refs)[:10]}\n"
            f"- MCP tools executed: {[t.tool_name for t in evidence.tool_calls]}\n\n"
            f"Tool-orchestration agent findings:\n{final_text}\n\n"
            "Format a clear, evidence-grounded security report preserving every version number, "
            "vulnerability ID, affected range, fixed version (or explicit absence thereof), and GitHub link. "
            "Do not invent any data or conflate possible GitHub matches with confirmed remediation."
        )
        gemini_result = await gemini_synthesize(
            prompt="Produce the final structured security report strictly from the verified evidence above.",
            context=synthesis_context,
        )
        if gemini_result.get("success"):
            final_text = gemini_result["text"]
            gemini_model_used = gemini_result.get("model")

    duration_ms = (time.monotonic_ns() - start_ns) / 1_000_000
    model_used = gemini_model_used or groq_model_used

    return ChatResponse(
        session_id=session_id,
        response=final_text or "The agent did not produce a response.",
        sources=evidence.sources,
        vulnerability_ids=sorted(evidence.vulnerability_ids),
        github_issue_refs=sorted(evidence.github_issue_refs),
        github_pr_refs=sorted(evidence.github_pr_refs),
        execution_trace=evidence.tool_calls,
        trace=evidence.tool_calls,
        groq_model_used=groq_model_used,
        gemini_model_used=gemini_model_used,
        model_used=model_used,
        total_tool_calls=len(evidence.tool_calls),
        iterations=iterations,
        total_duration_ms=round(duration_ms, 2),
        status="error" if agent_error else "completed",
        error_message=agent_error,
    )


def _find_tool(
    mcp_client: MCPClientManager,
    server_name: str,
    name_candidates: list[str],
    keywords: list[str],
) -> str | None:
    """Resolve a dynamically discovered MCP tool on a specific server by name or keywords."""
    for cand in name_candidates:
        info = mcp_client.tool_registry.get(cand)
        if info is not None and info.server_name == server_name:
            return cand
    for name, info in mcp_client.tool_registry.items():
        if info.server_name != server_name:
            continue
        hay = f"{name} {info.tool.description or ''}".lower()
        if any(kw in hay for kw in keywords):
            return name
    return None


def _correlate_github_records(
    items: list[dict[str, Any]],
    vuln_rows: list[dict[str, Any]],
    item_kind: str,
) -> list[dict[str, Any]]:
    """Classify real GitHub issues/PRs as confirmed_match, possible_match, or repo_activity."""
    vuln_ids_lower = {str(v["id"]).lower(): v["id"] for v in vuln_rows if v.get("id")}
    vuln_pkgs_lower = {
        str(v["package"]).lower(): v["package"] for v in vuln_rows if v.get("package")
    }

    enriched: list[dict[str, Any]] = []
    for item in items:
        title = str(item.get("title") or "")
        body = str(item.get("body") or "")
        haystack = f"{title}\n{body}".lower()

        matched_ids = [orig for low, orig in vuln_ids_lower.items() if low in haystack]
        matched_pkgs = [
            orig
            for low, orig in vuln_pkgs_lower.items()
            if re.search(rf"\b{re.escape(low)}\b", haystack)
        ]

        if matched_ids:
            correlation_status = "confirmed_match"
        elif matched_pkgs:
            correlation_status = "possible_match"
        else:
            correlation_status = "uncorrelated"

        enriched_item = dict(item)
        enriched_item["correlation_status"] = correlation_status
        enriched_item["matched_vulnerability_ids"] = matched_ids
        enriched_item["matched_packages"] = matched_pkgs
        enriched_item["item_kind"] = item_kind
        enriched.append(enriched_item)

    # Sort confirmed matches first, then possible matches, then others.
    rank = {"confirmed_match": 0, "possible_match": 1, "uncorrelated": 2}
    enriched.sort(key=lambda x: rank.get(x["correlation_status"], 3))
    return enriched


async def run_full_scan(
    owner: str,
    repo: str,
    mcp_client: MCPClientManager | None = None,
) -> dict[str, Any]:
    """Run a genuine cross-system scan strictly through both Synapse-generated MCP servers."""
    if mcp_client is None:
        mcp_client = get_mcp_client()

    if not mcp_client.tool_registry:
        await mcp_client.refresh_tools()

    evidence = EvidenceCollector()

    async def _exec(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        called_at = datetime.now(UTC).isoformat()
        res = await mcp_client.call_tool(tool_name, args, timeout=TOOL_CALL_TIMEOUT)
        info = mcp_client.tool_registry.get(tool_name)
        srv = res.get("server_name") or (info.server_name if info else "unknown")
        evidence.record_tool_call(
            server_name=srv,
            tool_name=tool_name,
            arguments=args,
            result=res,
            duration_ms=res.get("duration_ms"),
            called_at=called_at,
        )
        return res

    # 1. Fetch repository metadata via GitHub MCP
    repo_tool = _find_tool(
        mcp_client,
        "github-service-mcp",
        ["fetch_repository_metadata", "github_get_repository"],
        ["repository_metadata", "owner/repo", "metadata"],
    )
    if not repo_tool:
        raise RuntimeError(
            "GitHub repository metadata tool not found in discovered MCP tools."
        )
    repo_res = await _exec(repo_tool, {"owner": owner, "repo": repo})
    if not repo_res.get("success"):
        raise RuntimeError(
            repo_res.get("error") or f"Failed to fetch {owner}/{repo} via GitHub MCP"
        )

    # 2. Fetch dependency manifests via GitHub MCP
    deps_tool = _find_tool(
        mcp_client,
        "github-service-mcp",
        ["list_repository_dependencies", "github_get_dependencies"],
        ["dependencies", "manifest"],
    )
    if not deps_tool:
        raise RuntimeError(
            "GitHub dependencies tool not found in discovered MCP tools."
        )
    deps_res = await _exec(deps_tool, {"owner": owner, "repo": repo})
    if not deps_res.get("success"):
        raise RuntimeError(
            deps_res.get("error")
            or f"Failed to fetch dependencies for {owner}/{repo} via GitHub MCP"
        )

    deps_payload = deps_res.get("result", {})
    dependencies: list[dict[str, Any]] = deps_payload.get("dependencies") or []
    total_deps = int(deps_payload.get("total_dependencies", len(dependencies)))
    resolved_count = int(
        deps_payload.get(
            "resolved_count", sum(1 for d in dependencies if d.get("is_resolved"))
        )
    )
    unresolved_count = int(
        deps_payload.get("unresolved_count", total_deps - resolved_count)
    )

    # 3. Query OSV batch API via OSV MCP
    osv_tool = _find_tool(
        mcp_client,
        "osv-service-mcp",
        [
            "query_batch_vulnerabilities",
            "query_vulnerabilities_for_pinned_dependencies",
            "osv_query_vulnerabilities_batch",
        ],
        ["querybatch", "batch", "pinned_dependencies", "vulnerabilit"],
    )
    if not osv_tool:
        raise RuntimeError(
            "OSV batch vulnerability tool not found in discovered MCP tools."
        )
    batch_input = [
        {
            "package_name": d["package_name"],
            "ecosystem": d.get("ecosystem", "PyPI"),
            "installed_version": d.get("installed_version"),
        }
        for d in dependencies
    ]
    osv_res = await _exec(
        osv_tool, {"dependencies": batch_input, "include_details": True}
    )
    if not osv_res.get("success"):
        raise RuntimeError(
            osv_res.get("error") or "Failed to query OSV vulnerabilities via OSV MCP"
        )

    osv_payload = osv_res.get("result", {})
    vuln_pkgs_count = int(osv_payload.get("vulnerable_packages_count", 0))
    total_vulns = int(osv_payload.get("total_vulnerabilities_found", 0))

    vuln_rows: list[dict[str, Any]] = []
    for pkg_res in osv_payload.get("results") or []:
        if not isinstance(pkg_res, dict) or pkg_res.get("status") != "vulnerable":
            continue
        pkg_name = pkg_res.get("package_name")
        installed_ver = pkg_res.get("installed_version")
        vulns_detail = pkg_res.get("vulnerabilities") or []
        if not vulns_detail:
            for vid in pkg_res.get("vulnerability_ids") or []:
                vuln_rows.append(
                    {
                        "package": pkg_name,
                        "version": installed_ver,
                        "id": vid,
                        "severity": "UNKNOWN",
                        "affected_range": "See OSV record",
                        "fixed_version": None,
                        "source": "OSV",
                        "osv_url": f"https://osv.dev/vulnerability/{vid}",
                    }
                )
            continue

        for vuln in vulns_detail:
            ranges_txt = []
            for rng in vuln.get("affected_ranges") or []:
                intro = rng.get("introduced")
                fixed = rng.get("fixed")
                last_aff = rng.get("last_affected")
                if intro and fixed:
                    ranges_txt.append(f">={intro}, <{fixed}")
                elif intro and last_aff:
                    ranges_txt.append(f">={intro}, <={last_aff}")
                elif intro:
                    ranges_txt.append(f">={intro}")
                elif rng.get("versions"):
                    ranges_txt.append(f"{len(rng['versions'])} versions")

            fixed_list = vuln.get("fixed_versions") or []
            sev_label = vuln.get("severity_label")
            if not sev_label and vuln.get("severity"):
                first_sev = vuln["severity"][0]
                sev_label = first_sev.get("type") or "SUPPLIED"

            vuln_rows.append(
                {
                    "package": pkg_name,
                    "version": installed_ver,
                    "id": vuln.get("vulnerability_id"),
                    "severity": sev_label or "UNSPECIFIED",
                    "affected_range": "; ".join(ranges_txt)
                    if ranges_txt
                    else "Not specified by OSV",
                    "fixed_version": ", ".join(fixed_list) if fixed_list else None,
                    "source": "OSV",
                    "osv_url": vuln.get("osv_url"),
                    "summary": vuln.get("summary"),
                }
            )

    # 4. Fetch GitHub issues and PRs via GitHub MCP for cross-system correlation
    issues_tool = _find_tool(
        mcp_client,
        "github-service-mcp",
        ["list_repository_issues", "github_get_issues"],
        ["issues"],
    )
    pulls_tool = _find_tool(
        mcp_client,
        "github-service-mcp",
        ["list_repository_pull_requests", "github_get_pulls"],
        ["pull_request", "pulls"],
    )
    if not issues_tool or not pulls_tool:
        raise RuntimeError(
            "GitHub issues/pulls MCP tools not found in discovered registry."
        )

    issues_res = await _exec(
        issues_tool, {"owner": owner, "repo": repo, "state": "open", "per_page": 30}
    )
    if not issues_res.get("success"):
        raise RuntimeError(
            issues_res.get("error")
            or f"Failed to retrieve GitHub issues for {owner}/{repo} via MCP"
        )

    pulls_res = await _exec(
        pulls_tool, {"owner": owner, "repo": repo, "state": "open", "per_page": 30}
    )
    if not pulls_res.get("success"):
        raise RuntimeError(
            pulls_res.get("error")
            or f"Failed to retrieve GitHub pull requests for {owner}/{repo} via MCP"
        )

    raw_issues = (issues_res.get("result") or {}).get("issues", [])
    raw_pulls = (pulls_res.get("result") or {}).get("pull_requests", [])

    correlated_issues = _correlate_github_records(raw_issues, vuln_rows, "issue")
    correlated_pulls = _correlate_github_records(raw_pulls, vuln_rows, "pr")
    # Only count confirmed remediation matches (explicit CVE/GHSA/OSV ID match), never possible package mentions.
    open_remediation_prs = sum(
        1
        for pr in correlated_pulls
        if pr.get("state") == "open"
        and pr.get("correlation_status") == "confirmed_match"
    )

    return {
        "owner": owner,
        "repo": repo,
        "repository": repo_res.get("result", {}),
        "manifests_found": deps_payload.get("manifests_found", []),
        "total_dependencies": total_deps,
        "resolved_count": resolved_count,
        "unresolved_count": unresolved_count,
        "vulnerable_packages_count": vuln_pkgs_count,
        "total_vulnerabilities": total_vulns,
        "open_remediation_prs": open_remediation_prs,
        "dependencies": dependencies,
        "vulnerabilities": vuln_rows,
        "github": {
            "issues": correlated_issues,
            "pull_requests": correlated_pulls,
        },
        "vulnerability_ids": sorted({v["id"] for v in vuln_rows if v.get("id")}),
        "execution_trace": evidence.tool_calls,
    }


_COMMIT_SHA_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


async def run_commit_check(
    owner: str | None,
    repo: str | None,
    commit: str | None,
    mcp_client: MCPClientManager | None = None,
) -> dict[str, Any]:
    """Perform a cross-system commit lookup strictly via GitHub MCP and OSV MCP."""
    if mcp_client is None:
        mcp_client = get_mcp_client()

    if not mcp_client.tool_registry:
        await mcp_client.refresh_tools()

    evidence = EvidenceCollector()
    commit_url: str | None = None
    commit_message: str | None = None
    author: str | None = None
    authored_at: str | None = None
    target_sha = (commit or "").strip()

    if not target_sha:
        if not owner or not repo:
            raise ValueError(
                "Provide either a full 40/64-char Git commit SHA or a GitHub owner/repo."
            )
        commits_tool = _find_tool(
            mcp_client,
            "github-service-mcp",
            ["list_repository_commits", "github_get_commits"],
            ["commits", "commit history"],
        )
        if not commits_tool:
            raise RuntimeError(
                "GitHub commits tool is not available in discovered MCP tools."
            )
        called_at = datetime.now(UTC).isoformat()
        commits_res = await mcp_client.call_tool(
            commits_tool,
            {"owner": owner, "repo": repo, "page": 1, "per_page": 1},
            timeout=TOOL_CALL_TIMEOUT,
        )
        evidence.record_tool_call(
            server_name=commits_res.get("server_name") or "github-service-mcp",
            tool_name=commits_tool,
            arguments={"owner": owner, "repo": repo, "page": 1, "per_page": 1},
            result=commits_res,
            duration_ms=commits_res.get("duration_ms"),
            called_at=called_at,
        )
        if not commits_res.get("success"):
            raise RuntimeError(
                commits_res.get("error")
                or f"Failed to retrieve latest commit for {owner}/{repo} via GitHub MCP"
            )
        commits_list = (commits_res.get("result") or {}).get("commits") or []
        if not commits_list:
            raise RuntimeError(f"GitHub returned no commits for {owner}/{repo}.")
        latest = commits_list[0]
        target_sha = str(latest.get("sha") or "").strip()
        commit_url = latest.get("html_url")
        commit_message = latest.get("message")
        author = latest.get("author_login") or latest.get("author_name")
        authored_at = latest.get("authored_at")

    if not _COMMIT_SHA_RE.match(target_sha):
        raise ValueError(
            "Invalid commit hash: must be a full 40-character (SHA-1) or 64-character (SHA-256) hexadecimal Git commit SHA."
        )
    target_sha = target_sha.lower()
    if not commit_url and owner and repo:
        commit_url = f"https://github.com/{owner}/{repo}/commit/{target_sha}"

    osv_commit_tool = _find_tool(
        mcp_client,
        "osv-service-mcp",
        ["query_vulnerabilities_by_commit_hash", "query_vulnerabilities_by_git_commit"],
        ["commit"],
    )
    if not osv_commit_tool:
        raise RuntimeError(
            "OSV commit-query MCP tool is not available in discovered tools. Run synapse build --discover."
        )

    called_at = datetime.now(UTC).isoformat()
    osv_res = await mcp_client.call_tool(
        osv_commit_tool,
        {"commit": target_sha},
        timeout=TOOL_CALL_TIMEOUT,
    )
    evidence.record_tool_call(
        server_name=osv_res.get("server_name") or "osv-service-mcp",
        tool_name=osv_commit_tool,
        arguments={"commit": target_sha},
        result=osv_res,
        duration_ms=osv_res.get("duration_ms"),
        called_at=called_at,
    )
    if not osv_res.get("success"):
        raise RuntimeError(
            osv_res.get("error") or f"OSV commit lookup failed for {target_sha}"
        )

    payload = osv_res.get("result") or {}
    vulns = payload.get("vulnerabilities") or []
    return {
        "commit_hash": payload.get("commit_hash", target_sha),
        "commit_url": commit_url,
        "commit_message": commit_message,
        "author": author,
        "authored_at": authored_at,
        "vulnerability_count": int(payload.get("vulnerability_count", len(vulns))),
        "vulnerabilities": vulns,
        "source": payload.get("source", "osv_api"),
        "source_url": payload.get("source_url", "https://api.osv.dev/v1/query"),
        "fetched_at": payload.get("fetched_at", datetime.now(UTC).isoformat()),
        "http_status": int(payload.get("http_status", 200)),
        "cached": bool(payload.get("cached", False)),
        "data_freshness": payload.get("data_freshness", "live"),
        "execution_trace": evidence.tool_calls,
        "note": (
            "OSV returned zero vulnerability records associated with this commit. "
            "This does not establish that the repository is secure and does not replace dependency-version scanning."
            if not vulns
            else None
        ),
    }
