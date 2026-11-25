"""Tavily provider: external security advisory research for confirmed vulnerabilities."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)


async def tavily_search_vulnerability(
    vulnerability_id: str,
    package_name: str | None = None,
    max_results: int = 5,
) -> dict[str, Any]:
    """Search Tavily for external security advisory information about a confirmed vulnerability.

    OSV remains the authoritative vulnerability source. Tavily provides
    supplementary context (vendor advisories, patch notes, CVE details).
    Tavily results are NEVER used to classify a package as vulnerable.
    """
    api_key = os.getenv("TAVILY_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "TAVILY_API_KEY not configured. Tavily search is optional.",
            "vulnerability_id": vulnerability_id,
        }

    try:
        from tavily import AsyncTavilyClient

        client = AsyncTavilyClient(api_key=api_key)

        # Prefer official advisory and CVE sources
        query_parts = [vulnerability_id]
        if package_name:
            query_parts.append(package_name)
        query_parts.append("security advisory CVE")
        query = " ".join(query_parts)

        response = await client.search(
            query=query,
            max_results=max_results,
            include_domains=[
                "osv.dev",
                "nvd.nist.gov",
                "cve.mitre.org",
                "github.com/advisories",
                "pypi.org",
                "snyk.io",
                "security.snyk.io",
            ],
            include_answer=False,
        )

        results_raw = response.get("results") or []
        sanitized_results = []
        for item in results_raw:
            if isinstance(item, dict):
                sanitized_results.append(
                    {
                        "title": item.get("title"),
                        "url": item.get("url"),
                        "content_snippet": (item.get("content") or "")[:600],
                        "score": item.get("score"),
                        "published_date": item.get("published_date"),
                    }
                )

        return {
            "success": True,
            "vulnerability_id": vulnerability_id,
            "package_name": package_name,
            "query": query,
            "results": sanitized_results,
            "result_count": len(sanitized_results),
            "note": "Tavily results provide supplementary context only. OSV.dev is the authoritative vulnerability source.",
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Tavily search failed: {type(exc).__name__}: {exc}",
            "vulnerability_id": vulnerability_id,
        }


def is_tavily_available() -> bool:
    return bool(os.getenv("TAVILY_API_KEY"))
