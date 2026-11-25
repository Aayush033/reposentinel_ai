# RepoSentinel AI — Synapse-Powered Repository Security Copilot

**2nd Brain Labs x Geek Room Vibe-a-thon — Track 3: A copilot that works across two systems.**

RepoSentinel AI is a cross-system security copilot that connects **GitHub** (repository metadata, dependency manifests, issues, pull requests, and commits) with **OSV.dev** (open-source vulnerability advisories and fix versions) through **two genuine Synapse-generated MCP servers** and an evidence-grounded AI agent.

Every production result originates directly from live upstream APIs (`https://api.github.com`, `https://api.osv.dev`, `https://pypi.org/pypi`, Tavily when configured, Groq, and Gemini). No synthetic scans, mock findings, or fabricated scores exist in the application.

---

## Architecture Diagram

```
+-------------------------------------------------------------------+
|                  Security Operations Dashboard                     |
|         http://127.0.0.1:8000  (Vanilla HTML5 / CSS / JS)         |
+---------------------------------+---------------------------------+
                                  | HTTP / JSON
                                  v
+-------------------------------------------------------------------+
|               copilot_gateway (FastAPI, port 8000)                 |
|  - /api/scan, /api/chat, /api/mcp-tools, /api/refresh-tools       |
|  - Groq (tool orchestration: openai/gpt-oss-120b / 20b)           |
|  - Gemini (synthesis: gemini-3.8-flash / 3.5-flash-lite)          |
|  - Tavily (optional external advisory context)                    |
|  - SQLite + SQLAlchemy 2.x (scan history & audit trace)           |
|  - Official MCP Python SDK v2 ClientSession (stdio)               |
+-------------------+---------------------------+-------------------+
                    | MCP stdio                 | MCP stdio
                    v                           v
+-------------------------------+   +-------------------------------+
| github_service/               |   | osv_service/                  |
| synapse_auto_server.py        |   | synapse_auto_server.py        |
+---------------+---------------+   +---------------+---------------+
                | HTTP                              | HTTP
                v                                   v
+-------------------------------+   +-------------------------------+
| github_service (port 8001)    |   | osv_service (port 8002)       |
| - /repos/{owner}/{repo}       |   | - /vulnerabilities/query-batch|
| - .../dependencies            |   | - /vulnerabilities/{id}       |
| - .../issues, /pulls, /commits|   | + Demo 3: /registry/pypi/...  |
+---------------+---------------+   +---------------+---------------+
                |                                   |
                v                                   v
       https://api.github.com              https://api.osv.dev
                                           (+ https://pypi.org/pypi)
```

---

## Two Independent Systems

### System A: `github_service` (Port 8001)
- Queries `https://api.github.com` (public repos work unauthenticated; optional `GITHUB_TOKEN` supports higher rate limits and private read-only access).
- Parses `uv.lock`, `poetry.lock`, `requirements.txt`, and `pyproject.toml` via `packaging` and `tomllib`.
- Strictly marks non-exact version ranges (`>=`, `~=`, `^`, `*`) as `unresolved` rather than inventing versions.
- Caches live responses in SQLite with source URL, HTTP status, `fetched_at`, and cache TTL freshness.

### System B: `osv_service` (Port 8002)
- Queries `https://api.osv.dev/v1/querybatch` and `https://api.osv.dev/v1/vulns/{id}`.
- Skips unresolved dependency versions (`unresolved_skipped`) without classifying them as safe or vulnerable.
- Preserves exact OSV severity, affected ranges, and fixed versions (never invents CVSS scores or fix versions).
- Initially exposes only OSV endpoints; `demo_extensions/pypi_registry_router.py` adds `GET /registry/pypi/{package_name}/latest-release` live during Demo 3.

---

## Setup & Installation (Windows PowerShell)

### 1. Prerequisites
- **Python 3.12** (explicitly verified in `.venv`)
- **Node.js 20+** and **npm** (used via `npx` — no global Synapse install required)

### 2. Create Virtual Environment & Install Dependencies
```powershell
.\scripts\setup.ps1
```
Or manually:
```powershell
C:\Users\Aayush\AppData\Local\Programs\Python\Python312\python.exe -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

### 3. Configure API Keys
Copy `.env.example` to `.env` and fill in your keys:
```env
GITHUB_TOKEN=         # Optional for public repos; required for private repos or higher rate limits
GROQ_API_KEY=         # Required for AI agent orchestration & local Synapse generation
GEMINI_API_KEY=       # Optional; used for report synthesis (falls back to Groq if unavailable)
TAVILY_API_KEY=       # Optional; supplementary vendor/CVE research when requested

# OSV.dev is a public API and does NOT require an API key.
OSV_API_BASE=https://api.osv.dev
OSV_TIMEOUT_SECONDS=25
OSV_CACHE_TTL_SECONDS=300
```

> **OSV.dev Authentication:** OSV.dev (`https://api.osv.dev`) is a public vulnerability API and requires **no** API key. `GITHUB_TOKEN`, `GROQ_API_KEY`, `GEMINI_API_KEY`, and `TAVILY_API_KEY` are never sent to OSV.

### Commit-Hash & Version-Based OSV Queries

- **Version-based batch scan:** `POST /vulnerabilities/query-batch` (queries `https://api.osv.dev/v1/querybatch` for pinned dependencies).
- **Commit-hash lookup:** `POST /vulnerabilities/query-commit` (queries `https://api.osv.dev/v1/query` with `{"commit": "<full-sha>"}`).
- **Cross-system commit workflow:** The AI agent and the **Commit Lookup** dashboard tab fetch the real latest commit SHA from GitHub MCP (`list_repository_commits`) and pass that exact SHA into the Synapse-generated OSV commit-query MCP tool (`query_vulnerabilities_by_commit_hash`).

PowerShell test example against the public OSV API:
```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "https://api.osv.dev/v1/query" `
  -ContentType "application/json" `
  -Body '{"commit":"6879efc2c1596d11a6a6ad296f80063b558d5e0f"}'
```

### 4. Generate Both Synapse MCP Servers
```powershell
.\scripts\build_synapse.ps1
```
This configures Synapse with Groq (`openai/gpt-oss-120b`), disables telemetry (`SYNAPSE_TELEMETRY=0`), and runs:
```powershell
npx --yes @2ndbrainlabs-ai/synapse-cli model set groq --model openai/gpt-oss-120b --global
npx --yes @2ndbrainlabs-ai/synapse-cli build --auto --local --all-endpoints
```
separately inside `github_service/` and `osv_service/`.

---

## Starting the Application

```powershell
.\scripts\start_all.ps1
```

Service URLs:
- **Security Dashboard**: http://127.0.0.1:8000
- **Copilot Gateway OpenAPI**: http://127.0.0.1:8000/docs
- **GitHub Service OpenAPI**: http://127.0.0.1:8001/docs
- **OSV Service OpenAPI**: http://127.0.0.1:8002/docs

---

## Hackathon Demo Walkthrough

### Demo 1 — Cross-System Scan & Correlation
1. Enter an actual GitHub repository (e.g., `pallets/flask` or any Python repo with pinned dependencies) and click **Scan Repository**.
2. In **AI Copilot**, ask:
   > "Scan this repository and identify all dependencies with confirmed OSV vulnerabilities. Check whether any open GitHub issue or pull request already addresses each vulnerability."

### Demo 2 — Deep Cross-System Evidence
Ask:
> "For the highest-priority confirmed vulnerability, show its affected version range, fixed version if provided, related GitHub issues and open remediation pull requests."

### Demo 3 — Mandatory Live Endpoint Addition & `synapse build --discover`
Initially, `osv_service` has **no** PyPI registry endpoint and **no** PyPI MCP tool.
1. Register the genuine PyPI endpoint and restart `osv_service`:
   ```powershell
   .\scripts\activate_registry_demo.ps1
   ```
2. Run Synapse discovery on `osv_service`:
   ```powershell
   .\scripts\discover_new_tool.ps1
   ```
   (Under the hood, this runs `npx --yes @2ndbrainlabs-ai/synapse-cli build --auto --local --all-endpoints --discover` inside `osv_service/`.)
3. Open **MCP Inspector** in the dashboard and click **Refresh Tools** — the newly discovered PyPI release tool appears immediately.
4. Ask the **AI Copilot**:
   > "For the vulnerable packages in this repository, retrieve their current published PyPI releases and compare those versions with the installed versions and OSV fixed versions."

---

## Testing & Verification

```powershell
# Unit & local integration tests (no external API keys required)
.\.venv\Scripts\python.exe -m pytest tests/ -m "not live_api and not requires_groq and not requires_gemini and not requires_tavily" -v

# Full suite including live GitHub + OSV API tests
.\.venv\Scripts\python.exe -m pytest tests/ -v

# Ruff linting & formatting check
.\.venv\Scripts\python.exe -m ruff check github_service osv_service copilot_gateway demo_extensions
.\.venv\Scripts\python.exe -m ruff format --check github_service osv_service copilot_gateway demo_extensions

# End-to-end verification script
.\scripts\verify_all.ps1
```

---

## Known Limitations & Troubleshooting
- **GitHub Unauthenticated Rate Limits**: Without `GITHUB_TOKEN`, GitHub allows 60 requests/hour per IP. Add a read-only PAT to `.env` for heavy scanning.
- **Unresolved Dependencies**: Repositories that only define ranges (e.g., `requests>=2.0`) without a lockfile (`uv.lock` / `poetry.lock`) have `unresolved` dependencies; RepoSentinel intentionally refuses to guess installed versions.
- **Synapse `--local` Key Requirement**: Running `synapse build --auto --local` with `--provider groq` requires `GROQ_API_KEY` in `.env`.
- **MCP SDK v2 Compatibility**: `mcp==2.3.0` renamed `FastMCP` to `MCPServer` (`mcp.server.mcpserver`). `scripts/build_synapse.ps1` and `scripts/discover_new_tool.ps1` automatically adapt any v1 `FastMCP` import generated by `synapse-cli`.
