"""Post-generation compatibility adapter for Synapse CLI v0.1.9 passthrough servers.

Never adds or invents tools. Only upgrades Synapse's generated file so that:
1. `FastMCP` (mcp v1) is adapted to `MCPServer` (mcp v2.3.0).
2. Tools generated for POST/query-param endpoints forward their FastAPI body/query
   parameters instead of calling `requests.post(url)` with an empty payload.
3. HTTP errors return structured JSON error objects instead of uncaught exceptions.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def adapt_file(server_path: Path) -> None:
    src = server_path.read_text(encoding="utf-8")

    # 1. MCP SDK v2 compatibility: FastMCP -> MCPServer
    src = src.replace(
        "from mcp.server.fastmcp import FastMCP",
        "from mcp.server.mcpserver import MCPServer",
    )
    src = re.sub(r"mcp\s*=\s*FastMCP\(", "mcp = MCPServer(", src)

    default_url = (
        "http://127.0.0.1:8001"
        if "github_service" in str(server_path)
        else "http://127.0.0.1:8002"
    )

    # 2. Ensure Pydantic BaseModel and default _BASE_URL are available
    if "from pydantic import BaseModel" not in src:
        src = src.replace(
            "import requests",
            f'import requests\nfrom pydantic import BaseModel\n\n_BASE_URL = os.getenv("ENDPOINT_BASE_URL", "{default_url}").rstrip("/")',
        )

    # 3. Replace os.environ["ENDPOINT_BASE_URL"] with _BASE_URL
    src = src.replace('os.environ["ENDPOINT_BASE_URL"]', "_BASE_URL")
    src = src.replace("os.environ['ENDPOINT_BASE_URL']", "_BASE_URL")

    # 4. Wire parameters for Synapse-generated POST /vulnerabilities/query-batch
    src = re.sub(
        r"def (\w+)\(\) -> dict:\s*\n"
        r'(\s*)url = f"\{_BASE_URL\}/vulnerabilities/query-batch"\s*\n'
        r"\s*headers = \{\}\s*\n"
        r"\s*resp = requests\.post\(url, headers=headers\)",
        r"def \1(dependencies: list[dict[str, Any]], include_details: bool = True) -> dict:\n"
        r'\2url = f"{_BASE_URL}/vulnerabilities/query-batch"\n'
        r'\2payload = {"dependencies": dependencies, "include_details": include_details}\n'
        r"\2try:\n"
        r"\2    resp = requests.post(url, json=payload, timeout=35)\n"
        r"\2except requests.RequestException as exc:\n"
        r'\2    return {"error": f"Connection error: {exc}", "source_url": url}',
        src,
    )

    # 5. Wire parameters for Synapse-generated POST /vulnerabilities/query-commit
    src = re.sub(
        r"def (\w+)\(\) -> dict:\s*\n"
        r'(\s*)url = f"\{_BASE_URL\}/vulnerabilities/query-commit"\s*\n'
        r"\s*headers = \{\}\s*\n"
        r"\s*resp = requests\.post\(url, headers=headers\)",
        r"def \1(commit: str) -> dict:\n"
        r'\2url = f"{_BASE_URL}/vulnerabilities/query-commit"\n'
        r"\2try:\n"
        r'\2    resp = requests.post(url, json={"commit": commit}, timeout=35)\n'
        r"\2except requests.RequestException as exc:\n"
        r'\2    return {"error": f"Connection error: {exc}", "source_url": url}',
        src,
    )

    # 6. Wire query params for GitHub issues, pulls, and commits handlers
    src = re.sub(
        r"def (\w+)\(owner: Any = None, repo: Any = None\) -> dict:\s*\n"
        r'(\s*)url = f"\{_BASE_URL\}/repos/\{owner\}/\{repo\}/issues"\s*\n'
        r"\s*headers = \{\}\s*\n"
        r"\s*resp = requests\.get\(url, headers=headers\)",
        r'def \1(owner: str, repo: str, state: str = "open", page: int = 1, per_page: int = 30) -> dict:\n'
        r'\2url = f"{_BASE_URL}/repos/{owner}/{repo}/issues"\n'
        r'\2resp = requests.get(url, params={"state": state, "page": page, "per_page": per_page}, timeout=30)',
        src,
    )
    src = re.sub(
        r"def (\w+)\(owner: Any = None, repo: Any = None\) -> dict:\s*\n"
        r'(\s*)url = f"\{_BASE_URL\}/repos/\{owner\}/\{repo\}/pulls"\s*\n'
        r"\s*headers = \{\}\s*\n"
        r"\s*resp = requests\.get\(url, headers=headers\)",
        r'def \1(owner: str, repo: str, state: str = "open", page: int = 1, per_page: int = 30) -> dict:\n'
        r'\2url = f"{_BASE_URL}/repos/{owner}/{repo}/pulls"\n'
        r'\2resp = requests.get(url, params={"state": state, "page": page, "per_page": per_page}, timeout=30)',
        src,
    )
    src = re.sub(
        r"def (\w+)\(owner: Any = None, repo: Any = None\) -> dict:\s*\n"
        r'(\s*)url = f"\{_BASE_URL\}/repos/\{owner\}/\{repo\}/commits"\s*\n'
        r"\s*headers = \{\}\s*\n"
        r"\s*resp = requests\.get\(url, headers=headers\)",
        r"def \1(owner: str, repo: str, sha: str | None = None, page: int = 1, per_page: int = 20) -> dict:\n"
        r'\2url = f"{_BASE_URL}/repos/{owner}/{repo}/commits"\n'
        r'\2params: dict[str, Any] = {"page": page, "per_page": per_page}\n'
        r"\2if sha:\n"
        r'\2    params["sha"] = sha\n'
        r"\2resp = requests.get(url, params=params, timeout=30)",
        src,
    )

    # 7. Return structured JSON error instead of raising uncaught HTTPError
    src = src.replace(
        "    resp.raise_for_status()\n",
        '    if resp.status_code >= 400:\n        return {"error": f"HTTP {resp.status_code}", "detail": resp.text[:400], "source_url": url}\n',
    )

    server_path.write_text(src, encoding="utf-8")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        adapt_file(Path(arg))
