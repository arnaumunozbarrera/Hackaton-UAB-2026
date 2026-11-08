# Simulated SOC API serving only a new batch of alerts (default: data\demo_alertas_comunes.jsonl)
param([string]$Alerts = "data\demo_alertas_comunes.jsonl")
Set-Location (Split-Path $PSScriptRoot -Parent)
$py = if (Test-Path .venv\Scripts\python.exe) { ".venv\Scripts\python.exe" } else { "python" }
$env:TARVIA_ALERTS_FILE = $Alerts
& $py -m uvicorn src.demo_api:app --port 8000
