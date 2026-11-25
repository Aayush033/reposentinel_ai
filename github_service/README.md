# RepoSentinel GitHub Service (System A)

Independent FastAPI microservice running on port `8001` that interfaces directly with the live GitHub REST API (`https://api.github.com`).

## Endpoints

- `GET /health` — Service health, `GITHUB_TOKEN` configuration status (never exposes secrets), rate limit tracking, and SQLite cache stats.
- `GET /repos/{owner}/{repo}` — Live repository metadata.
- `GET /repos/{owner}/{repo}/dependencies` — Inspects `uv.lock`, `poetry.lock`, `requirements.txt`, and `pyproject.toml`, strictly distinguishing exact pinned versions from unresolved version ranges.
- `GET /repos/{owner}/{repo}/issues` — Paginated repository issues (`state=open|closed|all`).
- `GET /repos/{owner}/{repo}/pulls` — Paginated repository pull requests (`state=open|closed|all`).
- `GET /repos/{owner}/{repo}/commits` — Paginated repository commit history.

## Running Standalone

```powershell
..\.venv\Scripts\python.exe -m uvicorn github_service.main:app --host 127.0.0.1 --port 8001
```
