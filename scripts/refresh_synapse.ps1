# RepoSentinel AI - Refresh Synapse (MCP reconnect only)

$VENV = ".\.venv\Scripts\python.exe"
$ROOT = $PSScriptRoot | Split-Path -Parent

Set-Location $ROOT

Write-Host "Refreshing MCP tool discovery via gateway API..." -ForegroundColor Cyan

try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/refresh-tools" -UseBasicParsing -Method POST -TimeoutSec 30
    $data = $resp.Content | ConvertFrom-Json
    Write-Host "GitHub MCP: $($data.github_server_status)" -ForegroundColor Green
    Write-Host "OSV MCP:    $($data.osv_server_status)" -ForegroundColor Green
    Write-Host "Total tools discovered: $($data.total_tools)"
    $data.tools | ForEach-Object { Write-Host "  - [$($_.server_name)] $($_.tool_name)" }
} catch {
    Write-Warning "Could not reach gateway at http://127.0.0.1:8000: $_"
    
    # Fallback: direct verification
    Write-Host "Direct MCP server verification..."
    & $VENV -c "
import asyncio, sys
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def verify(name, script):
    params = StdioServerParameters(command=sys.executable, args=[script])
    try:
        async with asyncio.timeout(20):
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    tools = [t.name for t in (result.tools or [])]
                    print(f'{name}: {tools}')
    except Exception as e:
        print(f'{name} ERROR: {e}')

asyncio.run(verify('github-service-mcp', 'github_service/synapse_auto_server.py'))
asyncio.run(verify('osv-service-mcp', 'osv_service/synapse_auto_server.py'))
"
}
