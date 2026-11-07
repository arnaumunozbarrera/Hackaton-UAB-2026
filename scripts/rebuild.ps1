# Rebuild the database and every derived artefact from the delivered dataset (Windows PowerShell).
#   scripts\rebuild.ps1            full rebuild (about 3 minutes)
#   scripts\rebuild.ps1 -FromL2    keep the loaded data, recompute L2 + L3 + docs
param([switch]$FromL2)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path (Split-Path $PSScriptRoot -Parent) "db")
$py = if (Test-Path ..\.venv\Scripts\python.exe) { "..\.venv\Scripts\python.exe" } else { "python" }
function Run($a) { & $py @a; if ($LASTEXITCODE -ne 0) { throw "failed: $a" } }

if (-not $FromL2) {
    $mitre = @(); if (Test-Path enterprise-attack.json) { $mitre = @("--mitre", "enterprise-attack.json") }
    Run (@("build_db.py", "--data", "..\docs", "--out", "tarvia_soc.sqlite") + $mitre)
}
Run @("l2_correlate.py", "--db", "tarvia_soc.sqlite")
Run @("l3_reconstruct.py", "--db", "tarvia_soc.sqlite", "--reports", "reports")
Run @("catalog.py", "--db", "tarvia_soc.sqlite")
Run @("migrate_hybrid.py", "--db", "tarvia_soc.sqlite", "--stage", "docs")
Write-Host "Rebuild done: db\tarvia_soc.sqlite"
