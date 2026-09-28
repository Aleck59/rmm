#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs the InvMon server as a Windows service.
.DESCRIPTION
  Copies invmon-server.exe to Program Files, creates the ProgramData data
  directory with a restricted ACL, seeds server.yaml on first install, and
  registers the InvMonServer service (automatic delayed start).
.PARAMETER Start
  Start the service immediately after installation.
.EXAMPLE
  .\install.ps1 -Start
#>
[CmdletBinding()]
param(
    [switch]$Start
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$installDir = Join-Path $env:ProgramFiles 'InvMon\Server'
$dataDir = Join-Path $env:ProgramData 'InvMon\Server'

Write-Host "Installing InvMon server to $installDir"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Path (Join-Path $here 'invmon-server.exe') -Destination $installDir -Force

# Data directory with a restricted ACL (SYSTEM + Administrators only).
foreach ($d in @($dataDir, (Join-Path $dataDir 'tls'), (Join-Path $dataDir 'logs'), (Join-Path $dataDir 'secrets'))) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}
icacls $dataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

$configPath = Join-Path $dataDir 'server.yaml'
if (-not (Test-Path $configPath)) {
    Copy-Item -Path (Join-Path $here 'server.example.yaml') -Destination $configPath
    Write-Host "Seeded default config: $configPath"
}

$exe = Join-Path $installDir 'invmon-server.exe'
& $exe service install
if ($LASTEXITCODE -ne 0) { throw "service install failed ($LASTEXITCODE)" }

if ($Start) {
    & $exe service start
    if ($LASTEXITCODE -ne 0) { throw "service start failed ($LASTEXITCODE)" }
}

Write-Host ''
Write-Host 'InvMon server installed.' -ForegroundColor Green
Write-Host "  Config:  $configPath"
Write-Host "  Logs:    $(Join-Path $dataDir 'logs')"
Write-Host '  Next:    edit the config (TLS, public URL), then: Start-Service InvMonServer'
