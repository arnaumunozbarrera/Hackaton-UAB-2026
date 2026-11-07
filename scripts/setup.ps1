# One-time developer setup (Windows PowerShell).  Run from the repository root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (Get-Command py -ErrorAction SilentlyContinue) { $py = "py -3" } else { $py = "python" }
$ver = Invoke-Expression "$py -c `"import sys; print(sys.version_info >= (3, 10))`""
if ($ver -ne "True") { throw "Python 3.10+ is required" }

if (-not (Test-Path .venv)) { Invoke-Expression "$py -m venv .venv" }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
& .\.venv\Scripts\pre-commit.exe install

if (-not (Test-Path .env)) { Copy-Item .env.example .env }

$mitre = "db\enterprise-attack.json"
if (-not (Test-Path $mitre)) {
    Write-Host "Downloading MITRE ATT&CK Enterprise bundle..."
    Invoke-WebRequest "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" -OutFile $mitre
}
Write-Host "Setup done. Activate with: .\.venv\Scripts\Activate.ps1   then build with: scripts\rebuild.ps1"
