<#
    uninstall.ps1 - cleanly remove SecureVault from this machine.

    Reverses, in order:
      1. Hardening changes it can (best-effort -Revert on the modular scripts).
      2. The Explorer right-click shell integration (three HKCU keys).
      3. The Chrome/Edge native-messaging host registration.
      4. The install directory under %LOCALAPPDATA%\SecureVault.

    It is IDEMPOTENT (safe to run twice) and PRINTS every action. It never
    deletes your SecureVault.dat - move or back that up first if it lives inside
    the install dir and you want to keep it.

        .\uninstall.ps1                 full removal
        .\uninstall.ps1 -WhatIf         show what would happen, change nothing
        .\uninstall.ps1 -KeepHardening  only remove the app integration, leave
                                        hardening as-is (you can revert those
                                        scripts yourself later)
        .\uninstall.ps1 -InstallRoot D:\Apps\SecureVault
                                        uninstall a non-default install location

    You must still remove the unpacked extension from chrome://extensions /
    edge://extensions by hand - browsers cannot be scripted out of that.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'SecureVault'),
    [switch] $KeepHardening
)

$ErrorActionPreference = 'Continue'

function Say  { param($m) Write-Host "  $m" }
function Ok   { param($m) Write-Host "  [done] $m" -ForegroundColor Green }
function Skip { param($m) Write-Host "  [skip] $m" -ForegroundColor DarkGray }
function Warn { param($m) Write-Host "  [warn] $m" -ForegroundColor Yellow }

# Where to look for the scripts: the install dir if present, else this script's dir.
$scriptSrc = if (Test-Path $InstallRoot) { $InstallRoot } else { $PSScriptRoot }

Write-Host "==== UNINSTALL SECUREVAULT ====" -ForegroundColor Cyan
Write-Host "  install root : $InstallRoot"
Write-Host "  scripts from : $scriptSrc"
Write-Host ""

# --------------------------------------------------------- 1. revert hardening
function Invoke-Revert {
    param([string] $Name, [string[]] $ScriptArgs)
    $path = Join-Path $scriptSrc $Name
    if (-not (Test-Path $path)) { Skip "$Name not present"; return }
    if (-not $PSCmdlet.ShouldProcess($Name, "run -Revert")) { return }
    try {
        & $path @ScriptArgs
        Ok "$Name $($ScriptArgs -join ' ')"
    } catch {
        Warn "$Name revert reported: $($_.Exception.Message)"
    }
}

Write-Host "1. Reverting SecureVault integrations / hardening (best-effort)..." -ForegroundColor Cyan
Invoke-Revert 'Install-BrowserFill.ps1' @('-Revert')
Invoke-Revert 'Backup-SecureVault.ps1'  @('-Revert')
if (-not $KeepHardening) {
    # These are the reversible modular network/idle scripts. Each is a no-op if
    # it was never applied. Left out on purpose: Harden-Laptop / Fix-Gaps, whose
    # reverts are the dedicated Revert-*.ps1 you should run deliberately.
    Invoke-Revert 'Set-PrivateDoh.ps1'          @('-Revert')
    Invoke-Revert 'Set-EncryptedDns.ps1'        @('-Revert')
    Invoke-Revert 'Block-AllInbound.ps1'        @('-Revert')
    Invoke-Revert 'Block-HpSmartInternet.ps1'   @('-Revert')
    Invoke-Revert 'Reduce-IdleFootprint.ps1'    @('-Revert')
    Invoke-Revert 'Harden-Chrome.ps1'           @('-Revert')
} else {
    Skip 'network/DNS/idle/Chrome reverts (-KeepHardening)'
}
Write-Host ""

# ------------------------------------------------- 2. Explorer shell integration
Write-Host "2. Removing the Explorer right-click menu (HKCU)..." -ForegroundColor Cyan

# If a built exe is here, let it unregister its own (svshell) menu too.
$exe = Join-Path $InstallRoot 'SecureVault.exe'
if (Test-Path $exe) {
    if ($PSCmdlet.ShouldProcess('SecureVault.exe', 'unregister')) {
        try { & $exe unregister | Out-Null; Ok 'SecureVault.exe unregister' }
        catch { Warn "SecureVault.exe unregister: $($_.Exception.Message)" }
    }
}

# The exact keys install_shell_integration.ps1 / `SecureVault.exe register` create.
$shellKeys = @(
    'HKCU:\Software\Classes\*\shell\SecureVaultAdd',
    'HKCU:\Software\Classes\Directory\shell\SecureVaultAdd',
    'HKCU:\Software\Classes\Directory\Background\shell\SecureVault'
)
foreach ($k in $shellKeys) {
    if (Test-Path $k) {
        if ($PSCmdlet.ShouldProcess($k, 'remove registry key')) {
            try { Remove-Item $k -Recurse -Force; Ok "removed $k" }
            catch { Warn "could not remove ${k}: $($_.Exception.Message)" }
        }
    } else { Skip "$k (not present)" }
}
Write-Host ""

# --------------------------------------------- 3. native-messaging host registry
Write-Host "3. Removing the browser native-messaging host registration..." -ForegroundColor Cyan
$hostKeys = @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.securevault.autofill',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.securevault.autofill'
)
foreach ($k in $hostKeys) {
    if (Test-Path $k) {
        if ($PSCmdlet.ShouldProcess($k, 'remove registry key')) {
            try { Remove-Item $k -Recurse -Force; Ok "removed $k" }
            catch { Warn "could not remove ${k}: $($_.Exception.Message)" }
        }
    } else { Skip "$k (not present)" }
}
Write-Host ""

# --------------------------------------------------------- 4. delete install dir
Write-Host "4. Deleting the install directory..." -ForegroundColor Cyan
if (Test-Path $InstallRoot) {
    $dat = Get-ChildItem -Path $InstallRoot -Filter '*.dat' -Recurse -File -EA SilentlyContinue
    if ($dat) {
        Warn "This directory still contains vault data:"
        $dat | ForEach-Object { Warn "    $($_.FullName)  ($('{0:N2}' -f ($_.Length/1GB)) GB)" }
        Warn "Move these out first if you want to keep them. NOT deleting the directory."
    } elseif ($PSCmdlet.ShouldProcess($InstallRoot, 'delete directory')) {
        try { Remove-Item $InstallRoot -Recurse -Force; Ok "deleted $InstallRoot" }
        catch { Warn "could not delete ${InstallRoot}: $($_.Exception.Message)" }
    }
} else { Skip "$InstallRoot (not present)" }
Write-Host ""

Write-Host "==== DONE ====" -ForegroundColor Cyan
Write-Host "  Still to do by hand:" -ForegroundColor Yellow
Write-Host "    - Remove the SecureVault extension from chrome://extensions and edge://extensions" -ForegroundColor Yellow
Write-Host "    - Delete any SecureVault DoH .mobileconfig you installed on an iPhone" -ForegroundColor Yellow
Write-Host "    - Run the dedicated Revert-FixGaps.ps1 / Revert-NetworkHardening.ps1 if you applied" -ForegroundColor Yellow
Write-Host "      Harden-Laptop.ps1 or Fix-Gaps.ps1 (not auto-reverted above)" -ForegroundColor Yellow
