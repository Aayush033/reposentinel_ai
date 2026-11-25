"""
Live credential verification for RepoSentinel AI.

Verifies connectivity to: GitHub REST, OSV.dev (no key), Groq, Gemini, Tavily.
Never prints API key values. Exits non-zero on any failure.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# Load .env from project root (never override already-set env vars)
try:
    from dotenv import load_dotenv

    load_dotenv(_root / ".env", override=False)
except ImportError:
    pass

import httpx

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

results: list[tuple[str, str, str]] = []


def check(label: str, ok: bool, detail: str) -> None:
    status = PASS if ok else FAIL
    results.append((status, label, detail))
    print(f"[{status}] {label}: {detail}")


def warn(label: str, detail: str) -> None:
    results.append((WARN, label, detail))
    print(f"[{WARN}] {label}: {detail}")


# ── GitHub REST ──────────────────────────────────────────────────────────────
github_token = os.getenv("GITHUB_TOKEN", "")
check("GITHUB_TOKEN set", bool(github_token), "present" if github_token else "MISSING")

if github_token:
    try:
        resp = httpx.get(
            "https://api.github.com/rate_limit",
            headers={"Authorization": f"token {github_token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            remaining = resp.json().get("rate", {}).get("remaining", "?")
            check(
                "GitHub REST API", True, f"HTTP 200, rate_limit remaining={remaining}"
            )
        else:
            check("GitHub REST API", False, f"HTTP {resp.status_code}")
    except Exception as exc:  # noqa: BLE001
        check("GitHub REST API", False, f"Network error: {type(exc).__name__}: {exc}")
else:
    warn("GitHub REST API", "Skipped (no GITHUB_TOKEN)")

# ── OSV.dev (no key required) ────────────────────────────────────────────────
try:
    resp = httpx.post(
        "https://api.osv.dev/v1/query",
        json={"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"},
        timeout=15,
    )
    if resp.status_code == 200:
        vuln_count = len(resp.json().get("vulns") or [])
        check("OSV.dev commit query", True, f"HTTP 200, vulns={vuln_count}")
    else:
        check(
            "OSV.dev commit query", False, f"HTTP {resp.status_code}: {resp.text[:100]}"
        )
except Exception as exc:  # noqa: BLE001
    check("OSV.dev commit query", False, f"{type(exc).__name__}: {exc}")

try:
    resp = httpx.post(
        "https://api.osv.dev/v1/querybatch",
        json={
            "queries": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "version": "2.19.0",
                }
            ]
        },
        timeout=15,
    )
    if resp.status_code == 200:
        results_list = resp.json().get("results") or []
        check("OSV.dev batch query", True, f"HTTP 200, results={len(results_list)}")
    else:
        check("OSV.dev batch query", False, f"HTTP {resp.status_code}")
except Exception as exc:  # noqa: BLE001
    check("OSV.dev batch query", False, f"{type(exc).__name__}: {exc}")

# ── PyPI ─────────────────────────────────────────────────────────────────────
try:
    resp = httpx.get("https://pypi.org/pypi/flask/json", timeout=10)
    if resp.status_code == 200:
        pkg_name = resp.json().get("info", {}).get("name", "?")
        check("PyPI metadata", True, f"HTTP 200, package={pkg_name}")
    else:
        check("PyPI metadata", False, f"HTTP {resp.status_code}")
except Exception as exc:  # noqa: BLE001
    check("PyPI metadata", False, f"{type(exc).__name__}: {exc}")

# ── Groq & Gemini (Async) ────────────────────────────────────────────────────
groq_key = os.getenv("GROQ_API_KEY", "")
check("GROQ_API_KEY set", bool(groq_key), "present" if groq_key else "MISSING")

gemini_key = os.getenv("GEMINI_API_KEY", "")
check("GEMINI_API_KEY set", bool(gemini_key), "present" if gemini_key else "MISSING")


async def _check_ai_providers():
    if groq_key:
        try:
            from copilot_gateway.groq_provider import groq_chat_with_tools

            res = await groq_chat_with_tools(
                messages=[{"role": "user", "content": "Reply with VERIFIED only."}],
                max_tokens=20,
            )
            if res.get("success"):
                content = (
                    res["message"].content.strip()
                    if hasattr(res.get("message"), "content")
                    else str(res.get("message"))
                )
                check(
                    "Groq LLM API",
                    True,
                    f"Model {res.get('model')} replied: {content[:30]!r}",
                )
            else:
                check("Groq LLM API", False, f"Failed: {res.get('error')}")
        except Exception as exc:  # noqa: BLE001
            check("Groq LLM API", False, f"{type(exc).__name__}: {exc}")
    else:
        warn("Groq LLM API", "Skipped (no GROQ_API_KEY)")

    if gemini_key:
        try:
            from copilot_gateway.gemini_provider import gemini_synthesize

            res = await gemini_synthesize(prompt="Reply with VERIFIED only.")
            if res.get("success"):
                text = (res.get("text") or "").strip()
                check(
                    "Gemini API",
                    True,
                    f"Model {res.get('model')} replied: {text[:30]!r}",
                )
            else:
                check("Gemini API", False, f"Failed: {res.get('error')}")
        except Exception as exc:  # noqa: BLE001
            check("Gemini API", False, f"{type(exc).__name__}: {exc}")
    else:
        warn("Gemini API", "Skipped (no GEMINI_API_KEY)")


import asyncio

asyncio.run(_check_ai_providers())

# ── Tavily ───────────────────────────────────────────────────────────────────
tavily_key = os.getenv("TAVILY_API_KEY", "")
check("TAVILY_API_KEY set", bool(tavily_key), "present" if tavily_key else "MISSING")

if tavily_key:
    try:
        resp = httpx.post(
            "https://api.tavily.com/search",
            json={
                "api_key": tavily_key,
                "query": "python security vulnerability",
                "max_results": 1,
            },
            timeout=20,
        )
        if resp.status_code == 200:
            results_data = resp.json().get("results") or []
            check("Tavily Search API", True, f"HTTP 200, results={len(results_data)}")
        else:
            check(
                "Tavily Search API",
                False,
                f"HTTP {resp.status_code}: {resp.text[:200]}",
            )
    except Exception as exc:  # noqa: BLE001
        check("Tavily Search API", False, f"{type(exc).__name__}: {exc}")
else:
    warn("Tavily Search API", "Skipped (no TAVILY_API_KEY)")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
failures = [r for r in results if r[0] == FAIL]
warnings = [r for r in results if r[0] == WARN]
passes = [r for r in results if r[0] == PASS]

print(f"Results: {len(passes)} PASS, {len(warnings)} WARN, {len(failures)} FAIL")
if failures:
    print("FAILURES:")
    for _, label, detail in failures:
        print(f"  - {label}: {detail}")
    sys.exit(1)
else:
    print("All credential checks passed.")
    sys.exit(0)
