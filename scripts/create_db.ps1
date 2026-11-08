# Create and ingest the agreed SQLite model from the repository sources.
param([string]$Out = "data\tarvia.sqlite", [switch]$Replace)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath (Split-Path $PSScriptRoot -Parent)
$pythonExecutable = if (Test-Path -LiteralPath '.venv\Scripts\python.exe') { '.venv\Scripts\python.exe' } else { 'python' }
$buildArguments = @('-m', 'src.database.build', '--out', $Out)
if ($Replace) { $buildArguments += '--replace' }
& $pythonExecutable @buildArguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
