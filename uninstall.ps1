<#
    uninstall.ps1 - cleanly remove SecureVault from this machine.

    Reverses, in order:
      1. Hardening changes it can (best-effort -Revert on the modular scripts).
      2. The Explorer right-click shell integration (three HKCU keys).
      3. The Chrome/Edge native-messaging host registration.
      4. The install directory (%LOCALAPPDATA%\Programs\SecureVault).

    It deliberately KEEPS %LOCALAPPDATA%\SecureVault: that is user state, not
    app files - config.json records where your vault lives, signing_key.pem is
    the browser extension's identity, and backup-logs\ belongs to the backup
    task. Delete it by hand if you really want a clean slate.

    Useful when Inno's own unins000.exe will not run: it is unsigned, so a
    machine with Smart App Control or WDAC enforcing refuses to load it
    (CodeIntegrity 3077/3033). This script needs no signed binary.

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
    # The Inno installer puts the app in %LOCALAPPDATA%\Programs\SecureVault
    # ({autopf} under PrivilegesRequired=lowest). This used to default to
    # %LOCALAPPDATA%\SecureVault, which is the per-user CONFIG directory -
    # config.json, signing_key.pem, svhost_allowed.json, backup-logs. Running
    # this script with the old default deleted all of that and left the app
    # itself installed. Fall back to the old path only for a pre-installer
    # layout, recognised by SecureVault.exe actually being there.
    [string] $InstallRoot = $(
        $inno = Join-Path $env:LOCALAPPDATA 'Programs\SecureVault'
        $prev = Join-Path $env:LOCALAPPDATA 'SecureVault'
        if (Test-Path (Join-Path $inno 'SecureVault.exe')) { $inno }
        elseif (Test-Path (Join-Path $prev 'SecureVault.exe')) { $prev }
        else { $inno }),
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
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.securevault.autofill',
    # Quick Browser keeps Chromium's registry identity (its branding script
    # rewrites only BRANDING, the strings .grd and the theme icons), so plain
    # Chromium and Quick Browser share this key.
    'HKCU:\Software\Chromium\NativeMessagingHosts\com.securevault.autofill'
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

# --------------------------------------------- 3b. login autostart (HKCU Run)
Write-Host "3b. Removing the start-at-login entry..." -ForegroundColor Cyan
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runVal = 'QuickOpenSecureVault'
if ((Get-ItemProperty -Path $runKey -Name $runVal -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess("$runKey\$runVal", 'remove Run value')) {
        try { Remove-ItemProperty -Path $runKey -Name $runVal -Force; Ok "removed $runVal" }
        catch { Warn "could not remove ${runVal}: $($_.Exception.Message)" }
    }
} else { Skip "$runVal (not present)" }
Write-Host ""

# --------------------------------------------------------- 4. delete install dir
Write-Host "4. Deleting the install directory..." -ForegroundColor Cyan
if (Test-Path $InstallRoot) {
    $dat = Get-ChildItem -Path $InstallRoot -Filter '*.dat' -Recurse -File -EA SilentlyContinue
    if ($dat) {
        Warn "This directory still contains vault data:"
        $dat | ForEach-Object { Warn "    $($_.FullName)  ($('{0:N2}' -f ($_.Length/1GB)) GB)" }
        Warn "Move these out first if you want to keep them. NOT deleting the directory."
    } elseif (-not (Test-Path (Join-Path $InstallRoot 'SecureVault.exe'))) {
        # Refuse to recursively delete a directory that does not hold the app.
        # Cheap insurance against ever again pointing this at the config dir.
        Warn "$InstallRoot does not contain SecureVault.exe - refusing to delete it."
        Warn "Pass -InstallRoot explicitly if the app really lives elsewhere."
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
