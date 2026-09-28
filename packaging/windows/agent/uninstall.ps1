#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes the InvMon agent service and binaries.
.PARAMETER Purge
  Also delete the data directory (config, stored token). Off by default.
#>
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:ProgramFiles 'InvMon\Agent'
$dataDir = Join-Path $env:ProgramData 'InvMon\Agent'
$exe = Join-Path $installDir 'invmon-agent.exe'

if (Test-Path $exe) {
    & $exe service stop 2>$null
    & $exe service uninstall 2>$null
}

if (Test-Path $installDir) {
    Remove-Item -Recurse -Force $installDir
}

if ($Purge -and (Test-Path $dataDir)) {
    Remove-Item -Recurse -Force $dataDir
    Write-Host 'Data directory purged.'
} elseif (Test-Path $dataDir) {
    Write-Host "Data directory kept at $dataDir (use -Purge to remove)."
}

Write-Host 'InvMon agent uninstalled.' -ForegroundColor Green
