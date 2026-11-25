# RepoSentinel AI - Build Synapse MCP Servers
# Configures Groq (openai/gpt-oss-120b) and runs Synapse Auto mode for github_service and osv_service.

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
    Write-Host ".env loaded (secrets hidden)" -ForegroundColor DarkGray
}

if (-not $env:GROQ_API_KEY) {
    Write-Error "GROQ_API_KEY is not set in .env or environment. Synapse --local build with Groq requires GROQ_API_KEY."
    exit 1
}

function Convert-McpV1ToV2IfNeeded($filePath) {
    if (!(Test-Path $filePath)) { return }
    $content = Get-Content $filePath -Raw
    if ($content -match "from mcp\.server\.fastmcp import FastMCP") {
        Write-Host "  Adapting generated FastMCP import to MCP SDK v2 (MCPServer) in $filePath..." -ForegroundColor Yellow
        $content = $content -replace "from mcp\.server\.fastmcp import FastMCP", "from mcp.server.mcpserver import MCPServer"
        $content = $content -replace "mcp\s*=\s*FastMCP\(", "mcp = MCPServer("
        Set-Content -Path $filePath -Value $content -NoNewline -Encoding UTF8
    }
}

function Invoke-SynapseBuild($serviceDir, $baseUrl) {
    Write-Host "`n=== Building Synapse MCP Server for $serviceDir ===" -ForegroundColor Cyan
    Get-ChildItem -Path $serviceDir -Filter "synapse_auto_server*.py" -ErrorAction SilentlyContinue | Remove-Item -Force
    Push-Location $serviceDir
    try {
        Write-Host "Attempting: npx --yes @2ndbrainlabs-ai/synapse-cli -y build --auto --local --provider groq --model openai/gpt-oss-120b --all-endpoints --smart-names --base-url $baseUrl"
        npx --yes @2ndbrainlabs-ai/synapse-cli -y build --auto --local --provider groq --model openai/gpt-oss-120b --all-endpoints --smart-names --base-url $baseUrl
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "--smart-names build failed (exit $LASTEXITCODE). Retrying Auto mode without --smart-names..."
            npx --yes @2ndbrainlabs-ai/synapse-cli -y build --auto --local --provider groq --model openai/gpt-oss-120b --all-endpoints --base-url $baseUrl
            if ($LASTEXITCODE -ne 0) {
                throw "Synapse build failed for $serviceDir with exit code $LASTEXITCODE"
            }
        }
    } finally {
        Pop-Location
    }
    $serverFile = Join-Path $serviceDir "synapse_auto_server.py"
    if (!(Test-Path $serverFile)) {
        throw "Expected generated file not found: $serverFile"
    }
    & $VENV "scripts\adapt_synapse_server.py" $serverFile
    if ($LASTEXITCODE -ne 0) { throw "Failed to adapt $serverFile for MCP v2" }
    $sz = (Get-Item $serverFile).Length
    Write-Host "  [OK] Generated $serverFile ($sz bytes)" -ForegroundColor Green
}

Write-Host "`nConfiguring Synapse provider: groq (openai/gpt-oss-120b)..."
npx --yes @2ndbrainlabs-ai/synapse-cli model set groq --model openai/gpt-oss-120b --global
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to configure Synapse model provider."
    exit 1
}

Invoke-SynapseBuild "github_service" "http://127.0.0.1:8001"
Invoke-SynapseBuild "osv_service" "http://127.0.0.1:8002"

Write-Host "`n=== Verifying Generated MCP Servers ===" -ForegroundColor Cyan
& $VENV -c "
import asyncio, os, sys
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def verify(name, script, base_url):
    env = dict(os.environ)
    env['ENDPOINT_BASE_URL'] = base_url
    params = StdioServerParameters(command=sys.executable, args=[script], env=env)
    async with asyncio.timeout(20):
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                result = await session.list_tools()
                tools = [t.name for t in (result.tools or [])]
                print(f'  OK {name}: {len(tools)} tools -> {tools}')

asyncio.run(verify('github-service-mcp', 'github_service/synapse_auto_server.py', 'http://127.0.0.1:8001'))
asyncio.run(verify('osv-service-mcp', 'osv_service/synapse_auto_server.py', 'http://127.0.0.1:8002'))
"
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Host "`nSynapse build and verification completed." -ForegroundColor Green
