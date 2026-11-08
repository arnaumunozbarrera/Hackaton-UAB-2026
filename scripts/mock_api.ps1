# Start the simulated SOC API (http://127.0.0.1:8000/docs)
Set-Location (Join-Path (Split-Path $PSScriptRoot -Parent) "docs\06_herramientas")
$py = if (Test-Path ..\..\.venv\Scripts\python.exe) { "..\..\.venv\Scripts\python.exe" } else { "python" }
& $py -m uvicorn mock_soc_api:app --port 8000
