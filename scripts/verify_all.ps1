# RepoSentinel AI - Verify All Components (strict exit-code propagation)

$VENV = ".\.venv\Scripts\python.exe"
$ROOT = $PSScriptRoot | Split-Path -Parent

Set-Location $ROOT

Write-Host "`n=== RepoSentinel AI Verification ===" -ForegroundColor Cyan
$allPassed = $true

function Check($label, $ok) {
    if ($ok) { Write-Host "  [OK] $label" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $label" -ForegroundColor Red; $script:allPassed = $false }
}

# --- Python environment ---
Write-Host "`n[Python Environment]"
$pyVer = & $VENV --version 2>&1
Check "Python 3.12 venv ($pyVer)" ($LASTEXITCODE -eq 0 -and $pyVer -like "*3.12*")
& $VENV -m pip check 2>&1 | Out-Null
Check "pip check" ($LASTEXITCODE -eq 0)

# --- Required files ---
Write-Host "`n[Required Files]"
$files = @(
    "github_service\main.py", "github_service\synapse_auto_server.py",
    "osv_service\main.py", "osv_service\synapse_auto_server.py",
    "copilot_gateway\main.py", "copilot_gateway\mcp_client.py",
    "copilot_gateway\agent_orchestrator.py",
    "demo_extensions\pypi_registry_router.py",
    "requirements.txt", "requirements-lock.txt", ".env.example"
)
foreach ($f in $files) { Check $f (Test-Path $f) }

# --- Running HTTP Services ---
Write-Host "`n[Service Health]"
foreach ($pair in @(@("GitHub Service", "http://127.0.0.1:8001"), @("OSV Service", "http://127.0.0.1:8002"), @("Gateway", "http://127.0.0.1:8000"))) {
    try {
        $r = Invoke-WebRequest -Uri "$($pair[1])/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        Check "$($pair[0]) reachable" ($r.StatusCode -eq 200)
    } catch {
        Check "$($pair[0]) reachable" $false
    }
}

# --- MCP servers (strict dynamic tool discovery check) ---
Write-Host "`n[MCP Server Tool Discovery]"
$mcpOut = & $VENV -c "
import asyncio, os, sys
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def verify(name, script, base_url, min_tools, expected_keywords):
    env = dict(os.environ)
    env['ENDPOINT_BASE_URL'] = base_url
    params = StdioServerParameters(command=sys.executable, args=[script], env=env)
    async with asyncio.timeout(20):
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                result = await session.list_tools()
                tools = [t.name for t in (result.tools or [])]
                if len(tools) < min_tools:
                    raise SystemExit(f'{name}: expected >= {min_tools} tools, got {len(tools)}: {tools}')
                joined = ' '.join(tools).lower()
                for kw in expected_keywords:
                    if kw not in joined:
                        raise SystemExit(f'{name}: missing expected tool keyword {kw!r} in {tools}')
                print(f'PASS {name}: {tools}')

async def main():
    await verify('github-service-mcp', 'github_service/synapse_auto_server.py', 'http://127.0.0.1:8001', 6, ['dependenc', 'issue', 'pull', 'commit'])
    await verify('osv-service-mcp', 'osv_service/synapse_auto_server.py', 'http://127.0.0.1:8002', 4, ['vulnerabilit', 'commit'])

asyncio.run(main())
" 2>&1
$mcpExit = $LASTEXITCODE
$mcpOut | ForEach-Object { Write-Host "  $_" }
Check "MCP servers initialize & expose expected tools" ($mcpExit -eq 0)

# --- Linting & Formatting ---
Write-Host "`n[Code Quality]"
& $VENV -m ruff check . 2>&1 | Select-Object -Last 5
Check "Ruff check" ($LASTEXITCODE -eq 0)
& $VENV -m ruff format --check . 2>&1 | Select-Object -Last 5
Check "Ruff format check" ($LASTEXITCODE -eq 0)

# --- Automated Tests ---
Write-Host "`n[Pytest Suite]"
& $VENV -m pytest tests/ -v --tb=short
$pytestExit = $LASTEXITCODE
Check "Pytest suite" ($pytestExit -eq 0)

if ($allPassed) {
    Write-Host "`n=== ALL CHECKS PASSED ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n=== SOME CHECKS FAILED ===" -ForegroundColor Red
    exit 1
}
