<#
    install.ps1 - install SecureVault from this folder into a per-user location.

    Stages the program into %LOCALAPPDATA%\SecureVault, generates the browser
    autofill bridge config, and registers the Explorer right-click menu. No admin
    rights are needed for the per-user parts; the optional Chrome/Edge policy
    allowlist step (run separately via Install-BrowserFill.ps1 -Apply) needs an
    elevated prompt.

    This installs the SOURCE tree so you can run `py src\sv_app.py`. If a signed
    SecureVault.exe is present next to this script it is staged too and used for
    the shell integration. Building the .exe yourself is covered in docs/BUILD.md.

        .\install.ps1                     stage + wire autofill + Explorer menu
        .\install.ps1 -NoAutofill         skip the autofill bridge config
        .\install.ps1 -NoShell            skip the Explorer right-click menu
        .\install.ps1 -InstallRoot D:\Apps\SecureVault
                                          install somewhere other than the default

    Uninstall with .\uninstall.ps1.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallRoot = (Join-Path $env:LOCALAPPDATA 'SecureVault'),
    [switch] $NoAutofill,
    [switch] $NoShell
)

$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot

function Ok   { param($m) Write-Host "  [done] $m" -ForegroundColor Green }
function Info { param($m) Write-Host "  $m" }
function Warn { param($m) Write-Host "  [warn] $m" -ForegroundColor Yellow }

Write-Host "==== INSTALL SECUREVAULT ====" -ForegroundColor Cyan
Write-Host "  from : $src"
Write-Host "  to   : $InstallRoot"
Write-Host ""

# --------------------------------------------------------------- 1. stage files
Write-Host "1. Staging files..." -ForegroundColor Cyan
# When the bundled installer extracts straight into the install location, the
# source and destination are the same folder - the files are already staged, so
# copying would try to overwrite each file with itself. Detect that and skip.
$srcResolved = (Resolve-Path $src).Path.TrimEnd('\')
$dstResolved = if (Test-Path $InstallRoot) { (Resolve-Path $InstallRoot).Path.TrimEnd('\') } else { $InstallRoot.TrimEnd('\') }
$inPlace = ($srcResolved -eq $dstResolved)
if ($inPlace) {
    Ok "already in place at $InstallRoot - no copy needed"
} elseif ($PSCmdlet.ShouldProcess($InstallRoot, 'copy program files')) {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    foreach ($item in @('src', 'extension', 'nativehost', 'README.md', 'LICENSE', 'docs')) {
        $from = Join-Path $src $item
        if (Test-Path $from) {
            Copy-Item $from -Destination $InstallRoot -Recurse -Force
            Ok "staged $item"
        }
    }
    # copy the hardening scripts (repo-root *.ps1) so uninstall.ps1 can revert them
    Get-ChildItem -Path $src -Filter '*.ps1' -File |
        Where-Object { $_.Name -notin @('install.ps1', 'uninstall.ps1', 'Setup-SecureVault.ps1') } |
        ForEach-Object { Copy-Item $_.FullName -Destination $InstallRoot -Force }
    Copy-Item (Join-Path $src 'uninstall.ps1') -Destination $InstallRoot -Force -EA SilentlyContinue
    # stage a signed exe if the release shipped one
    $exeSrc = Join-Path $src 'SecureVault.exe'
    if (Test-Path $exeSrc) { Copy-Item $exeSrc -Destination $InstallRoot -Force; Ok 'staged SecureVault.exe' }
    else { Info 'no SecureVault.exe here - run from source with: py src\sv_app.py' }
}
Write-Host ""

# ------------------------------------------------------ 2. autofill bridge config
if (-not $NoAutofill) {
    Write-Host "2. Generating browser autofill config..." -ForegroundColor Cyan
    $setup = Join-Path $InstallRoot 'src\svautofill_setup.py'
    $py = Get-Command py -EA SilentlyContinue
    if (-not $py) { $py = Get-Command python -EA SilentlyContinue }
    if (-not $py) {
        Warn 'Python not found on PATH - skipping autofill config. Install Python 3.8+, then:'
        Warn "    py `"$setup`" apply --root `"$InstallRoot`""
    } elseif ($PSCmdlet.ShouldProcess($setup, 'apply')) {
        try {
            & $py.Source $setup apply --root $InstallRoot | Out-Null
            Ok 'autofill bridge config generated (run Install-BrowserFill.ps1 -Apply to register in browsers)'
        } catch { Warn "svautofill_setup apply: $($_.Exception.Message)" }
    }
} else { Write-Host "2. Skipping autofill config (-NoAutofill)" -ForegroundColor DarkGray }
Write-Host ""

# --------------------------------------------------- 3. Explorer shell integration
if (-not $NoShell) {
    Write-Host "3. Registering the Explorer right-click menu (HKCU)..." -ForegroundColor Cyan
    $exe = Join-Path $InstallRoot 'SecureVault.exe'
    $shellPs = Join-Path $InstallRoot 'src\install_shell_integration.ps1'
    if ((Test-Path $exe) -and $PSCmdlet.ShouldProcess('SecureVault.exe', 'register')) {
        try { & $exe register | Out-Null; Ok 'SecureVault.exe register' }
        catch { Warn "register: $($_.Exception.Message)" }
    } elseif ((Test-Path $shellPs) -and $PSCmdlet.ShouldProcess($shellPs, 'run')) {
        if (Test-Path $exe) { & $shellPs -ExePath $exe }
        else { Warn 'no exe to point the menu at yet - build it (docs/BUILD.md), then run SecureVault.exe register' }
    } else { Warn 'shell integration script not found' }
} else { Write-Host "3. Skipping Explorer menu (-NoShell)" -ForegroundColor DarkGray }
Write-Host ""

Write-Host "==== DONE ====" -ForegroundColor Cyan
Write-Host "  Launch:  py `"$InstallRoot\src\sv_app.py`"   (or SecureVault.exe if built/shipped)"
Write-Host "  Autofill: load the unpacked extension from `"$InstallRoot\extension`" - see docs/USAGE.md"
Write-Host "  Uninstall: .\uninstall.ps1"
