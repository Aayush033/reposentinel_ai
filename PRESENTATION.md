# RepoSentinel AI — Hackathon Pitch Deck
**Track 3: A Copilot Across Two Systems**
*2nd Brain Labs × Geek Room Vibe-a-thon*

---

## Slide 1: Title Slide
- **Project Name:** RepoSentinel AI
- **Tagline:** Synapse-Powered Cross-System Repository Security Copilot
- **Track:** Track 3 — A Copilot Across Two Systems
- **Author:** Aayush
- **Core Technology:** FastAPI, Synapse MCP CLI, Model Context Protocol (MCP v2.3.0), Groq (`openai/gpt-oss-120b`), Google Gemini (`gemini-3.5-flash-lite`), GitHub REST API, OSV.dev, PyPI.

---

## Slide 2: The Problem & The RepoSentinel Solution
### The Security Gap Between Systems
- Repository code, dependency manifests, and active PRs live in **GitHub**.
- Global vulnerability advisories and fixes live in **OSV.dev**.
- Engineers manually toggle between GitHub and OSV to verify vulnerabilities.
- Static scanners produce false positives and lack Git commit & PR context.
- Remediation status (whether an open PR fixes the CVE) remains fragmented.

### The RepoSentinel AI Solution
- Connects two independent FastAPI microservices through **Synapse-generated MCP servers**.
- **Copilot Gateway** orchestrates cross-system queries using Groq & Gemini.
- Correlates package versions AND Git commit SHAs directly with OSV advisories.
- Cross-references open PRs to confirm whether remediation is already underway.
- 100% genuine live upstream APIs with zero synthetic data.

---

## Slide 3: Two Independent Systems Connected via Synapse MCP
### System 1: GitHub Service (Port 8001)
- Fetches repo metadata, issues, PRs, and commit history from `https://api.github.com`.
- Parses `uv.lock`, `poetry.lock`, `requirements.txt`, and `pyproject.toml`.
- Separates exact pinned dependencies from unresolved ranges (no guessing).

### System 2: OSV Service (Port 8002)
- Performs batch vulnerability lookups on `https://api.osv.dev/v1/querybatch`.
- Queries commit-hash vulnerabilities via `https://api.osv.dev/v1/query`.
- Caches query responses in SQLite with TTL freshness.
- Provides live PyPI registry extension for latest release lookups.

### Copilot Gateway & Agent (Port 8000)
- Connects to both services via stdio MCP ClientSessions.
- Groq (`openai/gpt-oss-120b`) handles multi-turn dynamic tool routing.
- Gemini synthesizes deep security remediation summaries.
- Interactive HTML5 dashboard with live execution traces.

---

## Slide 4: Synapse MCP Integration & Dynamic Tool Registry
### Synapse Local Auto Mode
- Generated via: `synapse build --auto --local --all-endpoints` with Groq (`openai/gpt-oss-120b`).
- **GitHub MCP:** 6 tools (`get_service_health`, `fetch_repository_metadata`, `list_repository_dependencies`, `list_repository_issues`, `list_repository_pull_requests`, `list_repository_commits`).
- **OSV MCP:** 5 tools (`get_service_health_status`, `query_vulnerabilities_for_pinned_dependencies`, `fetch_vulnerability_advisory`, `query_vulnerabilities_by_git_commit`, `fetch_pypi_latest_release_version`).

### Cross-System Intelligence Workflows
- **Dependency Correlation:** GitHub manifest -> OSV batch query -> GitHub PR matching.
- **Git Commit Audit:** GitHub latest commit SHA -> OSV query-commit -> Security verdict.
- **Remediation Match Engine:** Verifies whether open PRs mention fixed version tags.

---

## Slide 5: Track 3 Core Requirement — Live Endpoint Discovery
### Live Endpoint Injection & Discovery
1. `osv_service` starts with only vulnerability query endpoints.
2. Live endpoint `GET /registry/pypi/{package_name}/latest-release` added via `activate_registry_demo.ps1`.
3. `synapse build --auto --local --all-endpoints --discover` runs in `osv_service/`.
4. Synapse discovers the new endpoint and generates the PyPI MCP tool.
5. Copilot Gateway hot-reloads registry without server restart and executes the newly discovered tool.

### Verifiable Proof of Live Discovery
- Tool Name: `fetch_pypi_latest_release_version`.
- Live upstream query to `https://pypi.org/pypi/{pkg}/json` verified.
- Agent compares installed version vs OSV fixed version vs latest PyPI release.

---

## Slide 6: OSV Commit Hash Vulnerability Intelligence
### Git Commit Security Inspection
- Standard vulnerability scanners only check package names and version strings.
- RepoSentinel queries OSV.dev with exact 40- or 64-char Git commit SHAs.
- Validates SHA regex, prevents injection, and handles pagination tokens.
- SQLite cache records `source_url`, response code, and `fetched_at` timestamp.

### Live OSV Verified Test Case
- **Target Commit:** `6879efc2c1596d11a6a6ad296f80063b558d5e0f`
- **Verified Findings:** 3 known vulnerabilities identified.
- **Identified Advisories:** `CVE-2023-25193`, `CVE-2026-22693`, `OSV-2020-484`.
- Agent explains zero-vulnerability caveat: 0 hits does not mean vulnerability-free.

---

## Slide 7: Engineering Excellence & Verification Metrics
- **Ruff & Quality:** Zero linter errors across all codebases (`ruff check .`, `ruff format --check .`).
- **Automated Tests:** 60 unit and integration tests passing.
- **Security & Safety:** Strict `.gitignore` protects secrets (`.env`, `.venv`, caches, DBs).
- **One-Click Automation:** PowerShell scripts for setup, Synapse generation, startup, and full verification.

---

## Slide 8: Submission Summary & Deliverables
- **GitHub Repository:** https://github.com/Aayush033/reposentinel_ai
- **Hackathon Track:** Track 3 — A Copilot Across Two Systems
- **License:** Open Source License
- **Presentation Deck:** `presentation.pptx` & `PRESENTATION.md` included in repository root.
