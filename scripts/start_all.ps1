# RepoSentinel AI - Start All Services
# Starts github_service (8001), osv_service (8002), and copilot_gateway (8000).
# Monitors processes and cleans up cleanly on Ctrl+C.

$ROOT = $PSScriptRoot | Split-Path -Parent
$VENV = Join-Path $ROOT ".venv\Scripts\python.exe"

if (!(Test-Path $VENV)) {
    Write-Error "Virtual environment python not found at $VENV. Run scripts\setup.ps1 first."
    exit 1
}

function Test-PortInUse($port) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect("127.0.0.1", $port)
        $tcp.Close()
        return $true
    } catch {
        return $false
    }
}

function Wait-ServiceReady($url, $name, $maxSeconds = 30) {
    $elapsed = 0
    while ($elapsed -lt $maxSeconds) {
        try {
            $resp = Invoke-WebRequest -Uri "$url/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                Write-Host "  [OK] $name ready at $url" -ForegroundColor Green
                return $true
            }
        } catch {}
        Start-Sleep -Seconds 1
        $elapsed++
    }
    Write-Error "  [FAIL] $name failed to pass /health after ${maxSeconds}s"
    return $false
}

Set-Location $ROOT

# Load .env securely without printing secret values
if (Test-Path ".env") {
    Get-Content ".env" | Where-Object { $_ -match "^[A-Za-z_][A-Za-z0-9_]*=.+" } | ForEach-Object {
        $key, $val = $_ -split "=", 2
        if ($val -and -not [string]::IsNullOrWhiteSpace($val)) {
            [System.Environment]::SetEnvironmentVariable($key.Trim(), $val.Trim(), "Process")
        }
    }
    Write-Host ".env loaded (secrets not printed)" -ForegroundColor DarkGray
}

# Check port availability
foreach ($port in @(8000, 8001, 8002)) {
    if (Test-PortInUse $port) {
        Write-Error "Port $port is already in use. Free port $port before starting RepoSentinel AI."
        exit 1
    }
}

New-Item -ItemType Directory -Force -Path "logs" | Out-Null
$pids = @()

try {
    Write-Host "`n=== Starting RepoSentinel AI ===" -ForegroundColor Cyan

    $ghProc = Start-Process -FilePath $VENV -ArgumentList "-m", "uvicorn", "github_service.main:app", "--host", "127.0.0.1", "--port", "8001" -WorkingDirectory $ROOT -RedirectStandardOutput "logs\github_service.out.log" -RedirectStandardError "logs\github_service.err.log" -PassThru -WindowStyle Hidden
    $pids += $ghProc.Id
    Write-Host "Started github_service (PID: $($ghProc.Id))"

    $osvProc = Start-Process -FilePath $VENV -ArgumentList "-m", "uvicorn", "osv_service.main:app", "--host", "127.0.0.1", "--port", "8002" -WorkingDirectory $ROOT -RedirectStandardOutput "logs\osv_service.out.log" -RedirectStandardError "logs\osv_service.err.log" -PassThru -WindowStyle Hidden
    $pids += $osvProc.Id
    Write-Host "Started osv_service (PID: $($osvProc.Id))"

    $ghOk = Wait-ServiceReady "http://127.0.0.1:8001" "GitHub Service"
    $osvOk = Wait-ServiceReady "http://127.0.0.1:8002" "OSV Service"
    if (-not ($ghOk -and $osvOk)) {
        throw "Backend services failed health checks. Inspect logs\*.err.log."
    }

    $gwProc = Start-Process -FilePath $VENV -ArgumentList "-m", "uvicorn", "copilot_gateway.main:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory $ROOT -RedirectStandardOutput "logs\copilot_gateway.out.log" -RedirectStandardError "logs\copilot_gateway.err.log" -PassThru -WindowStyle Hidden
    $pids += $gwProc.Id
    Write-Host "Started copilot_gateway (PID: $($gwProc.Id))"

    $gwOk = Wait-ServiceReady "http://127.0.0.1:8000" "Copilot Gateway"
    if (-not $gwOk) {
        throw "Copilot Gateway failed health check. Inspect logs\copilot_gateway.err.log."
    }

    Write-Host "`n=== Service URLs ===" -ForegroundColor Cyan
    Write-Host "Dashboard:      http://127.0.0.1:8000" -ForegroundColor Green
    Write-Host "Gateway Docs:   http://127.0.0.1:8000/docs"
    Write-Host "GitHub Service: http://127.0.0.1:8001/docs"
    Write-Host "OSV Service:    http://127.0.0.1:8002/docs"
    Write-Host "`nPress Ctrl+C to stop all services cleanly..." -ForegroundColor Yellow

    while ($true) {
        Start-Sleep -Seconds 2
        foreach ($procId in $pids) {
            if (!(Get-Process -Id $procId -ErrorAction SilentlyContinue)) {
                Write-Warning "Process $procId exited unexpectedly. Check logs\."
            }
        }
    }
} finally {
    Write-Host "`nStopping RepoSentinel AI processes..." -ForegroundColor Yellow
    foreach ($procId in $pids) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    Write-Host "All services stopped." -ForegroundColor Green
}
