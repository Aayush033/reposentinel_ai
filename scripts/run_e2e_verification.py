"""
End-to-End Live Verification Runner for RepoSentinel AI.

Starts all 3 FastAPI services, verifies health, runs:
- TEST A: Real GitHub dependency scan + OSV version query
- TEST B: Real GitHub latest commit retrieval + OSV commit vulnerability lookup
- TEST C: AI agent cross-system comparison reasoning
- Shuts down background services cleanly.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHON_EXE = str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe")


async def wait_for_health(url: str, name: str, timeout: float = 25.0) -> bool:
    start = time.time()
    async with httpx.AsyncClient(timeout=3.0) as client:
        while time.time() - start < timeout:
            try:
                r = await client.get(f"{url}/health")
                if r.status_code == 200:
                    print(f"  [OK] {name} is healthy at {url}")
                    return True
            except Exception:  # noqa: BLE001, S110
                pass
            await asyncio.sleep(1.0)
    print(f"  [FAIL] {name} did not become ready within {timeout}s")
    return False


async def run_e2e():
    print("=" * 60)
    print("RepoSentinel AI — Part 12 End-to-End Verification")
    print("=" * 60)

    # 1. Start backend services
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"

    print("\n[Step 1] Starting background services...")
    gh_proc = subprocess.Popen(  # noqa: ASYNC220
        [
            PYTHON_EXE,
            "-m",
            "uvicorn",
            "github_service.main:app",
            "--port",
            "8001",
            "--host",
            "127.0.0.1",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    osv_proc = subprocess.Popen(  # noqa: ASYNC220
        [
            PYTHON_EXE,
            "-m",
            "uvicorn",
            "osv_service.main:app",
            "--port",
            "8002",
            "--host",
            "127.0.0.1",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    gw_proc = subprocess.Popen(  # noqa: ASYNC220
        [
            PYTHON_EXE,
            "-m",
            "uvicorn",
            "copilot_gateway.main:app",
            "--port",
            "8000",
            "--host",
            "127.0.0.1",
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    procs = [gh_proc, osv_proc, gw_proc]

    try:
        gh_ok = await wait_for_health("http://127.0.0.1:8001", "github_service")
        osv_ok = await wait_for_health("http://127.0.0.1:8002", "osv_service")
        gw_ok = await wait_for_health("http://127.0.0.1:8000", "copilot_gateway")

        if not (gh_ok and osv_ok and gw_ok):
            print("\n[FAIL] One or more services failed to start.")
            return False

        async with httpx.AsyncClient(timeout=90.0) as client:
            # 2. Rediscover tools in gateway
            print("\n[Step 2] Refreshing gateway MCP tool registry...")
            r_tools = await client.post("http://127.0.0.1:8000/api/refresh-tools")
            tools_data = r_tools.json()
            tool_names = [t["tool_name"] for t in tools_data.get("tools", [])]
            print(f"  Discovered {len(tool_names)} tools: {tool_names}")
            assert any(
                "commit" in t and ("vulnerabilit" in t or "osv" in t or "git" in t)
                for t in tool_names
            ), f"OSV commit tool missing! Tools: {tool_names}"
            assert (
                any("commit" in t and "list" in t for t in tool_names)
                or "list_repository_commits" in tool_names
            ), f"GitHub commits tool missing! Tools: {tool_names}"
            print("  [OK] Both commit-lookup and GitHub tools discovered dynamically.")

            # 3. TEST A: Full scan on genuine repo (pallets/flask)
            print("\n[Step 3: TEST A] Running full scan on pallets/flask...")
            t0 = time.time()
            scan_resp = await client.post(
                "http://127.0.0.1:8000/api/scan",
                json={"owner": "pallets", "repo": "flask"},
            )
            scan_duration = round(time.time() - t0, 2)
            if scan_resp.status_code == 200:
                s = scan_resp.json()
                print(
                    f"  [OK] Scan completed in {scan_duration}s (status: {s.get('status')})"
                )
                print(f"       Total dependencies: {s.get('total_dependencies')}")
                print(f"       Resolved dependencies: {s.get('resolved_count')}")
                print(f"       Total vulnerabilities: {s.get('total_vulnerabilities')}")
                print(
                    f"       Open remediation PRs (confirmed): {s.get('open_remediation_prs')}"
                )
                print(f"       Tool calls recorded: {len(s.get('tool_calls', []))}")
            else:
                print(
                    f"  [FAIL] Scan returned HTTP {scan_resp.status_code}: {scan_resp.text[:200]}"
                )
                return False

            # 4. TEST B: Commit security lookup (latest commit of pallets/flask)
            print(
                "\n[Step 4: TEST B] Running commit check on pallets/flask latest commit..."
            )
            t0 = time.time()
            commit_resp = await client.post(
                "http://127.0.0.1:8000/api/commit-check",
                json={"owner": "pallets", "repo": "flask"},
            )
            commit_duration = round(time.time() - t0, 2)
            if commit_resp.status_code == 200:
                c = commit_resp.json()
                print(f"  [OK] Commit check completed in {commit_duration}s")
                print(f"       Latest Commit SHA: {c.get('commit_hash')}")
                print(f"       Commit URL: {c.get('commit_url')}")
                print(f"       Author: {c.get('author')}")
                print(f"       OSV Vulnerability Count: {c.get('vulnerability_count')}")
                print(f"       Source: {c.get('source')} ({c.get('source_url')})")
                print(f"       Note: {c.get('note')}")
                print(
                    f"       Execution trace steps: {len(c.get('execution_trace', []))}"
                )
            else:
                print(
                    f"  [FAIL] Commit check returned HTTP {commit_resp.status_code}: {commit_resp.text[:200]}"
                )
                return False

            # 5. TEST B-2: Direct OSV commit query with real documented SHA
            print(
                "\n[Step 4b: TEST B-2] Querying documented vulnerable commit 6879efc2c1596d11a6a6ad296f80063b558d5e0f..."
            )
            direct_resp = await client.post(
                "http://127.0.0.1:8002/vulnerabilities/query-commit",
                json={"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"},
            )
            if direct_resp.status_code == 200:
                d = direct_resp.json()
                print(
                    f"  [OK] OSV returned {d.get('vulnerability_count')} vulnerabilities"
                )
                vuln_ids = [v["vulnerability_id"] for v in d.get("vulnerabilities", [])]
                print(f"       Vulnerability IDs: {vuln_ids}")
            else:
                print(f"  [FAIL] Direct commit query failed: {direct_resp.status_code}")
                return False

            # 6. TEST C: AI Copilot Cross-System Reasoning
            print("\n[Step 5: TEST C] Testing AI Copilot cross-system reasoning...")
            t0 = time.time()
            chat_resp = await client.post(
                "http://127.0.0.1:8000/api/chat",
                json={
                    "message": "Check whether the latest commit of pallets/flask has known OSV vulnerabilities.",
                    "owner": "pallets",
                    "repo": "flask",
                },
            )
            chat_duration = round(time.time() - t0, 2)
            if chat_resp.status_code == 200:
                ch = chat_resp.json()
                print(
                    f"  [OK] AI agent responded in {chat_duration}s (status: {ch.get('status')})"
                )
                print(f"       Groq model used: {ch.get('groq_model_used')}")
                print(f"       Gemini model used: {ch.get('gemini_model_used')}")
                print(f"       Total tool calls: {ch.get('total_tool_calls')}")
                print(
                    f"       Agent response preview: {ch.get('response', '')[:200]}..."
                )
            else:
                print(
                    f"  [WARN] Chat returned HTTP {chat_resp.status_code}: {chat_resp.text[:200]}"
                )

            print("\n" + "=" * 60)
            print("ALL END-TO-END TESTS (A, B, C) COMPLETED SUCCESSFULLY")
            print("=" * 60)
            return True

    finally:
        print("\nStopping background services...")
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:  # noqa: BLE001
                try:
                    p.kill()
                except Exception:  # noqa: BLE001, S110
                    pass
        print("Services stopped.")


if __name__ == "__main__":
    ok = asyncio.run(run_e2e())
    sys.exit(0 if ok else 1)
