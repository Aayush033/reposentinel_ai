# RepoSentinel AI - Setup Script
# Verifies Python 3.12, creates .venv, upgrades pip, installs requirements, and verifies Node.js.

$ROOT = $PSScriptRoot | Split-Path -Parent
Set-Location $ROOT

$VENV = ".\.venv\Scripts\python.exe"
$PYTHON312 = $null

$candidates = @(
    "C:\Users\Aayush\AppData\Local\Programs\Python\Python312\python.exe",
    (Get-Command python3.12 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
)
foreach ($c in $candidates) {
    if ($c -and (Test-Path $c)) {
        $ver = & $c --version 2>&1
        if ($ver -match "Python 3\.12") {
            $PYTHON312 = $c
            break
        }
    }
}

if (-not $PYTHON312) {
    $py312Path = & py -3.12 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $py312Path) {
        $PYTHON312 = $py312Path.Trim()
    }
}

Write-Host "`n=== RepoSentinel AI Setup ===" -ForegroundColor Cyan

if (-not $PYTHON312) {
    Write-Error "Python 3.12 is required but was not found. Install Python 3.12 and re-run."
    exit 1
}

$pyver = & $PYTHON312 --version 2>&1
Write-Host "Python 3.12 verified: $pyver ($PYTHON312)" -ForegroundColor Green

if (!(Test-Path ".\.venv")) {
    Write-Host "Creating .venv..."
    & $PYTHON312 -m venv .venv
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to create .venv"; exit 1 }
}

Write-Host "Activating .venv and verifying executable..."
& .\.venv\Scripts\Activate.ps1
& $VENV --version
& $VENV -c "import sys; print('Executable:', sys.executable)"
& $VENV -m pip --version

Write-Host "Upgrading pip inside .venv..."
& $VENV -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { Write-Error "pip upgrade failed"; exit 1 }

Write-Host "Installing requirements.txt..."
& $VENV -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Error "pip install failed"; exit 1 }

Write-Host "Running pip check..."
& $VENV -m pip check
if ($LASTEXITCODE -ne 0) { Write-Error "pip check failed"; exit 1 }

Write-Host "Writing requirements-lock.txt..."
& $VENV -m pip freeze | Out-File -Encoding UTF8 "requirements-lock.txt"

Write-Host "Verifying Node.js 20+ and npm..."
$nodeVer = node --version 2>&1
$npmVer = npm --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Node.js 20+ and npm are required for Synapse CLI."
    exit 1
}
Write-Host "Node.js: $nodeVer | npm: $npmVer" -ForegroundColor Green

if (!(Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host ".env created from .env.example. Add your API keys before running." -ForegroundColor Yellow
}

Write-Host "`nSetup complete." -ForegroundColor Green
