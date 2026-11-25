"""
RepoSentinel AI — Automated Test Suite

Tests are organized by component:
1. dependency_parser — pure Python, no network
2. github_service — ASGI transport (network tests marked live_api)
3. osv_service — ASGI transport (network tests marked live_api)
4. mcp_client — MCP server via stdio (integration)
5. agent_orchestrator — integration, requires GROQ_API_KEY
6. database / history_service — isolated SQLite in temp dir

Markers:
  live_api — requires real network + optionally GITHUB_TOKEN
  requires_groq — requires GROQ_API_KEY
  requires_gemini — requires GEMINI_API_KEY
  mcp_integration — requires running github_service/osv_service processes

Run all unit tests (no credentials needed):
  .venv/Scripts/python.exe -m pytest tests/ -m "not live_api and not requires_groq and not requires_gemini and not mcp_integration" -v

Run with live API access:
  .venv/Scripts/python.exe -m pytest tests/ -v
"""
