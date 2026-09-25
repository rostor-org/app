<#
.SYNOPSIS
  Installs the Rostor Windows logon slice: deputy service + credential provider.
  Layout and registry keys are from docs/contracts/windows-logon.md §4.

  One-command install from the release bundle (rostor-windows-amd64.zip),
  elevated:

    powershell -ExecutionPolicy Bypass -File .\install.ps1 -CoreUrl https://core:8443 -Token <enrollment token>

.PARAMETER CoreUrl
  Core base URL, e.g. https://core.example:8443. With -Token, enrolls this
  workstation before the service is installed. Skipped (with a note) when
  C:\ProgramData\Rostor\deputy.json already exists, so re-running is safe.
.PARAMETER Token
  Single-use enrollment token minted by an admin (console → Devices).
.PARAMETER CaFile
  PEM file with the core CA, to verify the enrollment call itself. Without
  it the enrollment call skips TLS verification (the deputy's --insecure);
  the CA returned in the enrollment response is pinned for everything after.
.PARAMETER DeputyExe
  Path to rostor-deputy.exe (default: .\rostor-deputy.exe next to this script).
.PARAMETER CredProvDll
  Path to RostorCredProv.dll. If omitted or missing, the credential provider
  step is skipped and only the deputy is installed.
.PARAMETER MockCore
  Run the service with `run --mock-core` (no core needed; identifier
  "testuser" is allowed with any secret). Development only; cannot be
  combined with -CoreUrl/-Token.
.PARAMETER SkipCredProv
  Install the deputy only; do not touch System32 or the CP registry keys.
.PARAMETER ExcludeMicrosoftAccount
  Hide the "Microsoft account" tile from Sign-in options. The local
  password tile is deliberately left in place as the fallback.

  Must run elevated. Never touches existing local accounts; never filters the
  built-in password provider.
#>
[CmdletBinding()]
param(
    [string]$CoreUrl = '',
    [string]$Token = '',
    [string]$CaFile = '',
    [string]$DeputyExe = '',
    [string]$CredProvDll = '',
    [switch]$MockCore,
    [switch]$SkipCredProv,
    [switch]$ExcludeMicrosoftAccount
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# $PSScriptRoot is not usable in parameter defaults under PowerShell 5.1.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $DeputyExe)    { $DeputyExe    = Join-Path $scriptDir 'rostor-deputy.exe' }
if (-not $CredProvDll) { $CredProvDll = Join-Path $scriptDir 'RostorCredProv.dll' }

$InstallDir  = 'C:\Program Files\Rostor'
$ProgramData = 'C:\ProgramData\Rostor'
$DeputyJson   = Join-Path $ProgramData 'deputy.json'
$ServiceName = 'RostorDeputy'
$Clsid       = '{7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}'
$CpKey       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$Clsid"
$ClsidKey    = "HKLM:\SOFTWARE\Classes\CLSID\$Clsid"
$DllTarget   = Join-Path $env:SystemRoot 'System32\RostorCredProv.dll'

# Collected for the final summary.
$summary = New-Object System.Collections.ArrayList

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'install.ps1 must run elevated.'
}
if (-not (Test-Path $DeputyExe)) { throw "deputy binary not found: $DeputyExe" }

# --- argument checks (before touching anything) --------------------------
if ($MockCore -and ($CoreUrl -or $Token)) {
    throw '-MockCore cannot be combined with -CoreUrl/-Token.'
}
if (($CoreUrl -and -not $Token) -or ($Token -and -not $CoreUrl)) {
    throw '-CoreUrl and -Token must be given together.'
}
if ($CoreUrl -and $CoreUrl -notmatch '^https://') {
    throw "-CoreUrl must be an https:// URL (got $CoreUrl)."
}
if ($CaFile -and -not (Test-Path $CaFile)) { throw "CA file not found: $CaFile" }

# --- state directory with the §4 ACLs -------------------------------------
# SYSTEM: full; Administrators: full on the directory (they run enroll and
# pipe-test); everyone else: nothing. device.key gets its own tighter ACL
# from the deputy when it is written.
New-Item -ItemType Directory -Force -Path $ProgramData, (Join-Path $ProgramData 'logs') | Out-Null
& icacls $ProgramData /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls on $ProgramData failed ($LASTEXITCODE)" }

# --- migration from the old name (the service was RostorAgent, the binary
# rostor-agent.exe, the enrollment agent.json) so an upgrade keeps its
# enrollment, ledger and accounts without re-enrolling -----------------------
$oldService = Get-Service -Name 'RostorAgent' -ErrorAction SilentlyContinue
if ($oldService) {
    Write-Host 'renaming: removing the RostorAgent service (enrollment and accounts are kept)'
    $oldExe = Join-Path $InstallDir 'rostor-agent.exe'
    if (Test-Path $oldExe) { & $oldExe uninstall-service 2>$null }
    if (Get-Service -Name 'RostorAgent' -ErrorAction SilentlyContinue) {
        Stop-Service 'RostorAgent' -Force -ErrorAction SilentlyContinue
        & sc.exe delete 'RostorAgent' | Out-Null
    }
    Start-Sleep -Seconds 1
    Remove-Item -Force $oldExe -ErrorAction SilentlyContinue
}
$oldJson = Join-Path $ProgramData 'agent.json'
if ((Test-Path $oldJson) -and -not (Test-Path $DeputyJson)) {
    Rename-Item $oldJson $DeputyJson
    Write-Host "renamed $oldJson to $DeputyJson"
}

# --- deputy binary + service ----------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "service $ServiceName already present; removing it first"
    & (Join-Path $InstallDir 'rostor-deputy.exe') uninstall-service 2>$null
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $ServiceName | Out-Null
    }
    Start-Sleep -Seconds 1
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force $DeputyExe (Join-Path $InstallDir 'rostor-deputy.exe')
$deputy = Join-Path $InstallDir 'rostor-deputy.exe'
$tile = Join-Path (Split-Path -Parent $PSCommandPath) 'tile.bmp'
if (Test-Path $tile) { Copy-Item -Force $tile (Join-Path $InstallDir 'tile.bmp') }

# --- enrollment (before the service starts, so it comes up enrolled) -------
# The deputy refuses to overwrite an existing enrollment; we check first so a
# re-run with the same flags is a no-op rather than an error.
if ($MockCore) {
    [void]$summary.Add('core:      mock (development only; identifier "testuser" is allowed with any secret)')
} elseif (Test-Path $DeputyJson) {
    $cfg = Get-Content -Raw $DeputyJson | ConvertFrom-Json
    if ($CoreUrl) {
        Write-Host "already enrolled ($DeputyJson exists, core $($cfg.core_url)); skipping enrollment"
        if ($cfg.core_url.TrimEnd('/') -ne $CoreUrl.TrimEnd('/')) {
            Write-Warning "existing enrollment points at $($cfg.core_url), not $CoreUrl. To re-enroll: .\uninstall.ps1 -Purge, then run install.ps1 again."
        }
    }
    [void]$summary.Add("core:      $($cfg.core_url) (enrolled as $($cfg.device_id), kept)")
} elseif ($CoreUrl) {
    Write-Host "enrolling with $CoreUrl"
    $enrollArgs = "enroll --core-url `"$CoreUrl`" --token `"$Token`""
    if ($CaFile) {
        $enrollArgs += " --ca-file `"$((Resolve-Path $CaFile).Path)`""
    } else {
        # The core's CA is not known yet: it arrives in the enrollment
        # response and is pinned from then on. The token is single-use.
        $enrollArgs += ' --insecure'
    }
    # The deputy reports failures on stderr; capture both streams to files so
    # $ErrorActionPreference = 'Stop' does not turn stderr into an exception
    # before we can show the message (and so no cmd.exe quoting is involved).
    $outFile = Join-Path $env:TEMP 'rostor-enroll.out'
    $errFile = Join-Path $env:TEMP 'rostor-enroll.err'
    $p = Start-Process -FilePath $deputy -ArgumentList $enrollArgs -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $out = ((Get-Content -Raw $outFile -ErrorAction SilentlyContinue) + (Get-Content -Raw $errFile -ErrorAction SilentlyContinue))
    Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
    if ($null -eq $out) { $out = '' }
    if ($p.ExitCode -ne 0 -or -not (Test-Path $DeputyJson)) {
        throw "enrollment failed (exit $($p.ExitCode)); nothing installed yet beyond the binary.`n$($out.Trim())"
    }
    Write-Host $out.Trim()
    $cfg = Get-Content -Raw $DeputyJson | ConvertFrom-Json
    [void]$summary.Add("core:      $($cfg.core_url) (enrolled as $($cfg.device_id))")
} else {
    Write-Warning "not enrolled: no $DeputyJson and no -CoreUrl/-Token. The service will answer deputy.not_enrolled at logon until you enroll."
    [void]$summary.Add('core:      NOT ENROLLED - run install.ps1 -CoreUrl https://core:8443 -Token <token>')
}

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
& $deputy @svcArgs
if ($LASTEXITCODE -ne 0) { throw "install-service failed ($LASTEXITCODE)" }

$svc = Get-Service -Name $ServiceName
$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
Write-Host "service $ServiceName is $($svc.Status)"
[void]$summary.Add("service:   $ServiceName $($svc.Status) ($deputy)")

# Prove the pipe answers before registering anything into LogonUI.
# pipe-test prints its timing on stderr, which PowerShell would otherwise
# turn into a terminating error under $ErrorActionPreference = 'Stop'.
$ui = & cmd.exe /c "`"$deputy`" pipe-test --op ui 2>nul" | Out-String
if ($LASTEXITCODE -ne 0 -or $ui -notmatch '"ok":\s*true') {
    throw "deputy pipe did not answer the ui op; not registering the credential provider.`n$ui"
}
Write-Host 'deputy pipe answers ui op'

function Write-Summary {
    Write-Host ''
    Write-Host '==> Rostor install summary'
    foreach ($line in $summary) { Write-Host "  $line" }
    Write-Host "  logs:      $ProgramData\logs\deputy.log, credprov.log"
    Write-Host '  uninstall: .\uninstall.ps1 [-Purge]'
}

# --- credential provider ----------------------------------------------------
if ($SkipCredProv) {
    Write-Host 'skipping credential provider (-SkipCredProv)'
    [void]$summary.Add('tile:      not installed (-SkipCredProv)')
    Write-Summary
    return
}
if (-not (Test-Path $CredProvDll)) {
    Write-Host "credential provider DLL not found at $CredProvDll; deputy-only install"
    [void]$summary.Add("tile:      not installed (no DLL at $CredProvDll)")
    Write-Summary
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
[void]$summary.Add("tile:      registered ($DllTarget); lock the workstation to see it")
Write-Summary
