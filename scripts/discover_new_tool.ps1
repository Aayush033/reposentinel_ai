# RepoSentinel AI - Discover New MCP Tool (Demo 3)
# Runs `synapse build --auto --local --all-endpoints --discover` on osv_service
# after activate_registry_demo.ps1 registers GET /registry/pypi/{package_name}/latest-release.

$VENV = ".\.venv\Scripts\python.exe"
$ROOT = $PSScriptRoot | Split-Path -Parent

Set-Location $ROOT
$env:SYNAPSE_TELEMETRY = "0"

# Load .env securely (never print secrets)
if (Test-Path ".env") {
    Get-Content ".env" | Where-Object { $_ -match "^[A-Za-z_][A-Za-z0-9_]*=.+" } | ForEach-Object {
        $key, $val = $_ -split "=", 2
        if ($val -and -not [string]::IsNullOrWhiteSpace($val)) {
            [System.Environment]::SetEnvironmentVariable($key.Trim(), $val.Trim(), "Process")
        }
    }
}

if (-not $env:GROQ_API_KEY) {
    Write-Error "GROQ_API_KEY is not set in .env. Synapse --local --discover requires GROQ_API_KEY."
    exit 1
}

Write-Host "`n=== Demo 3: Synapse --discover on OSV Service ===" -ForegroundColor Cyan

# Verify osv_service is running with registry extension
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8002/health" -UseBasicParsing -TimeoutSec 5
    $data = $resp.Content | ConvertFrom-Json
    if (-not $data.registry_extension_active) {
        Write-Error "Registry extension is NOT active on osv_service. Run scripts\activate_registry_demo.ps1 first."
        exit 1
    }
    Write-Host "  [OK] osv_service registry extension confirmed active." -ForegroundColor Green
} catch {
    Write-Error "Cannot reach osv_service at http://127.0.0.1:8002. Start services first."
    exit 1
}

# Verify new endpoint is live
try {
    $epResp = Invoke-WebRequest -Uri "http://127.0.0.1:8002/registry/pypi/requests/latest-release" -UseBasicParsing -TimeoutSec 10
    $epData = $epResp.Content | ConvertFrom-Json
    Write-Host "  [OK] New HTTP endpoint live: requests latest = $($epData.latest_version)" -ForegroundColor Green
} catch {
    Write-Error "New PyPI endpoint not responding: $_"
    exit 1
}

# Run synapse build --discover (remove prior generated file so Synapse writes directly to synapse_auto_server.py)
Get-ChildItem -Path "osv_service" -Filter "synapse_auto_server*.py" -ErrorAction SilentlyContinue | Remove-Item -Force
Push-Location "osv_service"
try {
    Write-Host "`nRunning: npx --yes @2ndbrainlabs-ai/synapse-cli -y build --auto --local --provider groq --model openai/gpt-oss-120b --all-endpoints --smart-names --discover --base-url http://127.0.0.1:8002"
    npx --yes @2ndbrainlabs-ai/synapse-cli -y build --auto --local --provider groq --model openai/gpt-oss-120b --all-endpoints --smart-names --discover --base-url http://127.0.0.1:8002
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "--smart-names failed; retrying --discover without --smart-names..."
        npx --yes @2ndbrainlabs-ai/synapse-cli -y build --auto --local --provider groq --model openai/gpt-oss-120b --all-endpoints --discover --base-url http://127.0.0.1:8002
        if ($LASTEXITCODE -ne 0) {
            throw "synapse build --discover failed with exit code $LASTEXITCODE"
        }
    }
} finally {
    Pop-Location
}

# Ensure MCP SDK v2 compatibility and POST/query parameter forwarding
$serverFile = "osv_service\synapse_auto_server.py"
& $VENV "scripts\adapt_synapse_server.py" $serverFile
if ($LASTEXITCODE -ne 0) { exit 1 }

# Verify the MCP server now exposes the newly discovered tool
Write-Host "`nVerifying OSV MCP server tool discovery..."
& $VENV -c "
import asyncio, os, sys
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def verify():
    env = dict(os.environ)
    env['ENDPOINT_BASE_URL'] = 'http://127.0.0.1:8002'
    params = StdioServerParameters(command=sys.executable, args=['osv_service/synapse_auto_server.py'], env=env)
    async with asyncio.timeout(20):
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                result = await session.list_tools()
                tools = [t.name for t in (result.tools or [])]
                print('Discovered OSV MCP tools:', tools)
                if not any('pypi' in t.lower() or 'registry' in t.lower() or 'latest' in t.lower() for t in tools):
                    raise SystemExit('ERROR: New registry tool was not discovered!')
                print('SUCCESS: New PyPI registry MCP tool discovered!')

asyncio.run(verify())
"
if ($LASTEXITCODE -ne 0) { exit 1 }

# Also refresh gateway tools if gateway is running
try {
    $refreshResp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/refresh-tools" -UseBasicParsing -Method POST -TimeoutSec 20
    $refreshData = $refreshResp.Content | ConvertFrom-Json
    Write-Host "  [OK] Gateway refreshed: $($refreshData.total_tools) total MCP tools active." -ForegroundColor Green
} catch {
    Write-Host "  Note: Gateway not running or refresh manually in UI via 'Refresh Tools'." -ForegroundColor Yellow
}
