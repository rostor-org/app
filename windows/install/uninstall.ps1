<#
.SYNOPSIS
  Removes the Rostor credential provider and agent service. Order matters:
  registry keys first (so LogonUI stops loading the DLL), then the DLL, then
  the service. Enrollment and the account ledger under C:\ProgramData\Rostor
  are kept unless -Purge.

.PARAMETER Purge
  Also delete C:\ProgramData\Rostor. Local accounts the agent created are
  never deleted (contract §3).
#>
[CmdletBinding()]
param(
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'

$InstallDir  = 'C:\Program Files\Rostor'
$ProgramData = 'C:\ProgramData\Rostor'
$ServiceName = 'RostorAgent'
$Clsid       = '{7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}'
$CpKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$Clsid"
$ClsidKey    = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$DllTarget   = Join-Path $env:SystemRoot 'System32\RostorCredProv.dll'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'uninstall.ps1 must run elevated.'
}

# 1. registry keys
foreach ($k in @($CpKey, $ClsidKey)) {
    if (Test-Path $k) {
        Remove-Item -Path $k -Recurse -Force
        Write-Host "removed $k"
    }
}

# 2. DLL. LogonUI may still hold it if the lock screen was shown since
#    registration; a rename-then-delete-on-reboot fallback covers that.
if (Test-Path $DllTarget) {
    try {
        Remove-Item -Force $DllTarget
        Write-Host "removed $DllTarget"
    } catch {
        $stale = "$DllTarget.old"
        Move-Item -Force $DllTarget $stale
        Write-Host "DLL in use; renamed to $stale (delete after next reboot)"
    }
}

# 3. service
$agent = Join-Path $InstallDir 'rostor-agent.exe'
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    if (Test-Path $agent) {
        & $agent uninstall-service
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    Write-Host "removed service $ServiceName"
}
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "removed $InstallDir"
}

# 4. state
if ($Purge) {
    if (Test-Path $ProgramData) {
        Remove-Item -Recurse -Force $ProgramData
        Write-Host "purged $ProgramData"
    }
} else {
    Write-Host "kept $ProgramData (enrollment, ledger, logs); use -Purge to remove"
}
Write-Host 'Local accounts created by the agent are left in place by design.'
