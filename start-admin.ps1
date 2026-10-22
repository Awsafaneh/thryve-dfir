$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Start-Process -FilePath "powershell.exe" -Verb RunAs -WindowStyle Normal -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + (Join-Path $ProjectRoot 'start-admin.ps1') + '"')
    )
    exit
}

Set-Location -LiteralPath $ProjectRoot
python .\app.py
