# RepoSentinel OSV Vulnerability Service (System B)

Independent FastAPI microservice running on port `8002` that queries the live public OSV.dev API (`https://api.osv.dev`).

> **Note:** OSV.dev is a public vulnerability API and **does not require an API key** (`OSV_API_KEY` is neither needed nor used). `GITHUB_TOKEN`, `GROQ_API_KEY`, `GEMINI_API_KEY`, and `TAVILY_API_KEY` are never sent to OSV.

## Endpoints

- `GET /health` — Service health, OSV base URL, cache stats, and registry extension status.
- `POST /vulnerabilities/query-batch` — Queries `POST https://api.osv.dev/v1/querybatch` for pinned dependency versions and optionally hydrates `/v1/vulns/{id}`. Unresolved versions are skipped and never classified as safe or vulnerable.
- `POST /vulnerabilities/query-commit` — Queries `POST https://api.osv.dev/v1/query` by exact 40/64-char Git commit SHA (`{"commit": "<sha>"}`) with `next_page_token` pagination and SQLite provenance caching.
- `GET /vulnerabilities/{vulnerability_id}` — Queries `GET https://api.osv.dev/v1/vulns/{vulnerability_id}` for affected ranges, fixed versions (when provided), references, and severity.

## Direct PowerShell Test Examples

### Commit-Hash Query (Public OSV API)
```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "https://api.osv.dev/v1/query" `
  -ContentType "application/json" `
  -Body '{"commit":"6879efc2c1596d11a6a6ad296f80063b558d5e0f"}'
```

### Package-Version Query (Local Service)
```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8002/vulnerabilities/query-batch" `
  -ContentType "application/json" `
  -Body '{"dependencies":[{"package_name":"requests","ecosystem":"PyPI","installed_version":"2.19.0"}]}'
```

## Live Demo Extension

During the live `synapse build --discover` demonstration, `demo_extensions/pypi_registry_router.py` is registered onto this service to expose:

- `GET /registry/pypi/{package_name}/latest-release`

## Running Standalone

```powershell
.\.venv\Scripts\python.exe -m uvicorn osv_service.main:app --host 127.0.0.1 --port 8002
```
