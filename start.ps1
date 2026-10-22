$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot

Write-Host "Starting Thryve on http://127.0.0.1:8765" -ForegroundColor Cyan
Write-Host "Tip: Run PowerShell as Administrator to read the Security log and full process metadata." -ForegroundColor Yellow
python .\app.py
