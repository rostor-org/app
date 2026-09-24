<#
.SYNOPSIS
  Installs the Rostor Windows logon slice: agent service + credential provider.
  Layout and registry keys are from docs/contracts/windows-logon.md §4.

.PARAMETER AgentExe
  Path to rostor-agent.exe (default: .\rostor-agent.exe next to this script).
.PARAMETER CredProvDll
  Path to RostorCredProv.dll. If omitted or missing, the credential provider
  step is skipped and only the agent is installed.
.PARAMETER MockCore
  Run the service with `run --mock-core` (no core needed; identifier
  "testuser" is allowed with any secret). Development only.
.PARAMETER SkipCredProv
  Install the agent only; do not touch System32 or the CP registry keys.

  Must run elevated. Never touches existing local accounts; never filters the
  built-in password provider.
#>
[CmdletBinding()]
param(
    [string]$AgentExe = '',
    [string]$CredProvDll = '',
    [switch]$MockCore,
    [switch]$SkipCredProv,
    # Hide the "Microsoft account" tile from Sign-in options. The local
    # password tile is deliberately left in place as the fallback.
    [switch]$ExcludeMicrosoftAccount
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# $PSScriptRoot is not usable in parameter defaults under PowerShell 5.1.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $AgentExe)    { $AgentExe    = Join-Path $scriptDir 'rostor-agent.exe' }
if (-not $CredProvDll) { $CredProvDll = Join-Path $scriptDir 'RostorCredProv.dll' }

$InstallDir  = 'C:\Program Files\Rostor'
$ProgramData = 'C:\ProgramData\Rostor'
$ServiceName = 'RostorAgent'
$Clsid       = '{7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}'
$CpKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$Clsid"
$ClsidKey    = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$DllTarget   = Join-Path $env:SystemRoot 'System32\RostorCredProv.dll'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'install.ps1 must run elevated.'
}
if (-not (Test-Path $AgentExe)) { throw "agent binary not found: $AgentExe" }

# --- state directory with the §4 ACLs -------------------------------------
# SYSTEM: full; Administrators: full on the directory (they run enroll and
# pipe-test); everyone else: nothing. device.key gets its own tighter ACL
# from the agent when it is written.
New-Item -ItemType Directory -Force -Path $ProgramData, (Join-Path $ProgramData 'logs') | Out-Null
& icacls $ProgramData /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls on $ProgramData failed ($LASTEXITCODE)" }

# --- agent binary + service ----------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "service $ServiceName already present; removing it first"
    & (Join-Path $InstallDir 'rostor-agent.exe') uninstall-service 2>$null
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    Start-Sleep -Seconds 1
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $AgentExe (Join-Path $InstallDir 'rostor-agent.exe')
$tile = Join-Path (Split-Path -Parent $PSCommandPath) 'tile.bmp'
if (Test-Path $tile) { Copy-Item -Force $tile (Join-Path $InstallDir 'tile.bmp') }

# Shared-workstation sign-in: never show the last user's tile. On a workgroup
# machine this is also what makes Windows 10 offer the "Other user" form,
# which is where a provider credential without a user SID is listed.
$pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -Path $pol -Name dontdisplaylastusername -Value 1 -Type DWord
if ($ExcludeMicrosoftAccount) {
    # WLIDCredentialProvider = the "Microsoft account" tile. PasswordProvider
    # ({60b78e88-...}) is never excluded.
    Set-ItemProperty -Path $pol -Name ExcludedCredentialProviders -Value '{F8A0B131-5F68-486c-8040-7E8FC3C85BB6}' -Type String
    Write-Host "excluded the Microsoft account sign-in tile (local password tile kept)"
}

$svcArgs = @('install-service')
if ($MockCore) { $svcArgs += '--mock-core' }
& (Join-Path $InstallDir 'rostor-agent.exe') @svcArgs
if ($LASTEXITCODE -ne 0) { throw "install-service failed ($LASTEXITCODE)" }

$svc = Get-Service -Name $ServiceName
$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
Write-Host "service $ServiceName is $($svc.Status)"

# Prove the pipe answers before registering anything into LogonUI.
# pipe-test prints its timing on stderr, which PowerShell would otherwise
# turn into a terminating error under $ErrorActionPreference = 'Stop'.
$ui = & cmd.exe /c "`"$InstallDir\rostor-agent.exe`" pipe-test --op ui 2>nul" | Out-String
if ($LASTEXITCODE -ne 0 -or $ui -notmatch '"ok":\s*true') {
    throw "agent pipe did not answer the ui op; not registering the credential provider.`n$ui"
}
Write-Host 'agent pipe answers ui op'

# --- credential provider ----------------------------------------------------
if ($SkipCredProv) {
    Write-Host 'skipping credential provider (-SkipCredProv)'
    return
}
if (-not (Test-Path $CredProvDll)) {
    Write-Host "credential provider DLL not found at $CredProvDll; agent-only install"
    return
}

# LogonUI keeps the DLL mapped while a lock screen is showing; Windows lets
# a mapped file be renamed but not overwritten, so move the old one aside
# and let the next LogonUI pick up the new file.
$old = "$DllTarget.old"
Remove-Item $old -Force -ErrorAction SilentlyContinue
try { Copy-Item -Force $CredProvDll $DllTarget }
catch [System.IO.IOException] {
    Rename-Item $DllTarget $old
    Copy-Item -Force $CredProvDll $DllTarget
    Write-Host "provider DLL was in use; replaced via rename (takes effect at the next lock screen)"
}

New-Item -Path $CpKey -Force | Out-Null
Set-ItemProperty -Path $CpKey -Name '(Default)' -Value 'RostorCredProv'

New-Item -Path $ClsidKey -Force | Out-Null
Set-ItemProperty -Path $ClsidKey -Name '(Default)' -Value 'RostorCredProv'
New-Item -Path "$ClsidKey\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "$ClsidKey\InprocServer32" -Name '(Default)' -Value 'RostorCredProv.dll'
Set-ItemProperty -Path "$ClsidKey\InprocServer32" -Name 'ThreadingModel' -Value 'Apartment'

Write-Host "credential provider registered ($Clsid); DLL at $DllTarget"
Write-Host 'The built-in password provider is untouched. Lock the workstation to see the Rostor tile.'
