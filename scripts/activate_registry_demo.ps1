# RepoSentinel AI - Activate PyPI Registry Demo Extension
# Reliably stops the existing osv_service on port 8002, registers the PyPI
# registry router, starts a new osv_service process, and verifies port 8002.

$ROOT = $PSScriptRoot | Split-Path -Parent
$VENV = Join-Path $ROOT ".venv\Scripts\python.exe"

Set-Location $ROOT

Write-Host "`n=== Demo 3: Activate PyPI Registry Extension ===" -ForegroundColor Cyan
Write-Host "This adds GET /registry/pypi/{package_name}/latest-release to osv_service."

# 1. Reliably locate and stop existing osv_service processes via CIM + TCP port 8002
Write-Host "`nStopping running osv_service (port 8002)..."
$targetPids = @()

$cimProcs = Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*osv_service*" -or $_.CommandLine -like "*8002*" }
foreach ($p in $cimProcs) {
    if ($p.ProcessId) { $targetPids += [int]$p.ProcessId }
}

$tcpListeners = Get-NetTCPConnection -LocalPort 8002 -State Listen -ErrorAction SilentlyContinue
foreach ($conn in $tcpListeners) {
    $procId = [int]$conn.OwningProcess
    if ($procId -gt 0) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue
        if ($p -and ($p.CommandLine -like "*osv_service*" -or $p.CommandLine -like "*uvicorn*")) {
            $targetPids += $procId
        } else {
            Write-Error "Port 8002 is owned by an unrelated process '$($p.Name)' (PID: $procId, Cmd: $($p.CommandLine)). Aborting to protect unrelated processes."
            exit 1
        }
    }
}

$targetPids = $targetPids | Select-Object -Unique
if ($targetPids.Count -gt 0) {
    foreach ($procId in $targetPids) {
        Write-Host "  Stopping PID $procId..."
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    # Wait up to 10s for port 8002 to be released
    $wait = 0
    while ($wait -lt 20) {
        $stillListening = Get-NetTCPConnection -LocalPort 8002 -State Listen -ErrorAction SilentlyContinue
        if (-not $stillListening) { break }
        Start-Sleep -Milliseconds 500
        $wait++
    }
    Write-Host "  osv_service stopped." -ForegroundColor Green
} else {
    Write-Host "  No existing osv_service process found on port 8002." -ForegroundColor Yellow
}

# 2. Patch osv_service/main.py to include the PyPI registry endpoint
$mainPath = "osv_service\main.py"
$content = Get-Content $mainPath -Raw

$patchSignature = "get_pypi_latest_release"

if ($content -notmatch $patchSignature) {
    Write-Host "Patching osv_service/main.py to include PyPI registry router..."
    $endpointCode = @"

from demo_extensions.pypi_registry_router import router as pypi_registry_router
from osv_service.package_registry import fetch_pypi_latest_release, PyPIAPIError

@app.get("/registry/pypi/{package_name}/latest-release", summary="Get the latest published release for a PyPI package")
async def get_pypi_latest_release(package_name: str):
    """Query https://pypi.org/pypi/{package_name}/json for the real latest published version."""
    try:
        return await fetch_pypi_latest_release(package_name)
    except PyPIAPIError as err:
        raise HTTPException(status_code=err.status_code, detail={"error": err.message, "source_url": err.source_url})
"@
    $newContent = $content -replace "(app = FastAPI\([^)]+\))", "`$1`n$endpointCode"
    Set-Content -Path $mainPath -Value $newContent -NoNewline -Encoding UTF8
    Write-Host "  [OK] Registry endpoint registered." -ForegroundColor Green
} else {
    Write-Host "  Registry endpoint already registered." -ForegroundColor DarkGray
}

# 3. Start new osv_service and retain its exact PID
Write-Host "`nStarting osv_service on port 8002..."
New-Item -ItemType Directory -Force -Path "logs" | Out-Null
$osvJob = Start-Process -FilePath $VENV -ArgumentList "-m", "uvicorn", "osv_service.main:app", "--host", "127.0.0.1", "--port", "8002" -WorkingDirectory $ROOT -RedirectStandardOutput "logs\osv_service.out.log" -RedirectStandardError "logs\osv_service.err.log" -PassThru -WindowStyle Hidden
$newPid = $osvJob.Id
Write-Host "  New osv_service PID: $newPid"

# 4. Verify osv_service is listening on 8002 and /health reports registry_extension_active=true
$elapsed = 0
$ready = $false
$servingPid = $null
while ($elapsed -lt 30) {
    Start-Sleep -Seconds 1
    $elapsed++
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8002/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $healthData = $resp.Content | ConvertFrom-Json
            $conn = Get-NetTCPConnection -LocalPort 8002 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($healthData.registry_extension_active -and $conn) {
                $servingPid = $conn.OwningProcess
                $ready = $true
                break
            }
        }
    } catch {}
}

if (-not $ready) {
    Write-Error "osv_service did not become ready on port 8002 with registry extension active. Check logs\osv_service.err.log."
    exit 1
}

Write-Host "`n[OK] osv_service PID $servingPid listening on port 8002 with registry extension active." -ForegroundColor Green

try {
    $testResp = Invoke-WebRequest -Uri "http://127.0.0.1:8002/registry/pypi/requests/latest-release" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    $data = $testResp.Content | ConvertFrom-Json
    Write-Host "[OK] New endpoint verified: requests latest = $($data.latest_version)" -ForegroundColor Green
    Write-Host "     Source URL: $($data.source_url)"
} catch {
    Write-Error "New PyPI endpoint verification failed: $_"
    exit 1
}

Write-Host "`nNext step: run scripts\discover_new_tool.ps1 to regenerate the OSV MCP server." -ForegroundColor Cyan
