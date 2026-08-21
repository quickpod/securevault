<#
    Install-BrowserFill.ps1 - register the SecureVault Autofill extension +
    native-messaging host in Chrome AND Edge, and allowlist the extension so it
    loads despite the Chrome/Edge extension blocklist from Harden-Chrome.ps1.

        (no switch)   read-only status
        -Apply        generate keys/IDs, write configs, register host, allowlist
        -Revert       remove registration + policy allowlist (leaves the vault
                      and the generated keys alone)

    Same house rules as the other scripts (see the revert-first pattern):
      - HKCU native-host registration needs no admin.
      - The policy allowlist writes HKLM\SOFTWARE\Policies\... and needs an
        elevated prompt; without it, everything else still installs and the
        script tells you exactly which elevated step remains.
      - -Revert needs no network and no state file.

    After -Apply you STILL must, by hand (browsers cannot be scripted into it):
      1. chrome://extensions and edge://extensions -> enable Developer mode
      2. "Load unpacked" -> %LOCALAPPDATA%\SecureVault\extension
      3. confirm the ID matches the one this script prints
    Autofill only works while SecureVault.exe is open and unlocked.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param([switch] $Apply, [switch] $Revert)

$ErrorActionPreference = 'Stop'
$Root   = "$env:LOCALAPPDATA\SecureVault"   # your install dir - edit to match
$Py     = 'python'                          # or a full path to python.exe
$Setup  = Join-Path $Root 'src\svautofill_setup.py'
$HostNm = 'com.securevault.autofill'

# per-browser: native-host key (HKCU) and policy hive (HKLM)
$Browsers = @(
    @{ Name='Chrome'; Native='HKCU:\Software\Google\Chrome\NativeMessagingHosts';
       Policy='HKLM:\SOFTWARE\Policies\Google\Chrome' },
    @{ Name='Edge';   Native='HKCU:\Software\Microsoft\Edge\NativeMessagingHosts';
       Policy='HKLM:\SOFTWARE\Policies\Microsoft\Edge' },
    # Quick Browser keeps Chromium's registry identity: branding/apply-branding.py
    # rewrites BRANDING, the strings .grd and the theme icons only, so the
    # registry key and user-data dir stay Chromium's. Plain Chromium lands here
    # too, which is correct - same key, same host.
    @{ Name='Quick Browser'; Native='HKCU:\Software\Chromium\NativeMessagingHosts';
       Policy='HKLM:\SOFTWARE\Policies\Chromium' }
)

function Test-Elevated {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Info {
    if (-not (Test-Path $Py)) { throw "Python not found at $Py (see the build memo)." }
    $action = if ($Apply) { 'apply' } else { 'status' }
    $json = & $Py $Setup $action --root $Root 2>$null | Out-String
    return $json | ConvertFrom-Json
}

# ------------------------------------------------------------------ allowlist
# Append an ID to a browser's ExtensionInstallAllowlist\<n> without disturbing
# existing numbered values. New-Item -Force on an existing key wipes it, so we
# only create when absent (the ServiceDll lesson).
function Add-Allowlist {
    param($PolicyKey, $Id)
    $listKey = "$PolicyKey\ExtensionInstallAllowlist"
    if (-not (Test-Path $listKey)) { New-Item -Path $listKey -Force | Out-Null }
    $item = Get-Item $listKey
    foreach ($n in $item.GetValueNames()) { if ($item.GetValue($n) -eq $Id) { return } }
    $idx = 1; while ($item.GetValueNames() -contains "$idx") { $idx++ }
    New-ItemProperty -Path $listKey -Name "$idx" -PropertyType String -Value $Id -Force | Out-Null
}

function Remove-Allowlist {
    param($PolicyKey, $Id)
    $listKey = "$PolicyKey\ExtensionInstallAllowlist"
    if (-not (Test-Path $listKey)) { return }
    $item = Get-Item $listKey
    foreach ($n in $item.GetValueNames()) {
        if ($item.GetValue($n) -eq $Id) { Remove-ItemProperty -Path $listKey -Name $n -Force }
    }
}

# --------------------------------------------------------------------- status
function Show-Status {
    Write-Host "==== SECUREVAULT BROWSER AUTOFILL ====" -ForegroundColor Cyan
    $info = Get-Info
    if ($info.ext_id) { "  extension id : $($info.ext_id)" }
    else { Write-Host "  not set up yet - run -Apply" -ForegroundColor Yellow; return }
    "  files:"
    $info.files.PSObject.Properties | ForEach-Object { "     {0,-14} {1}" -f $_.Name, $_.Value }
    foreach ($b in $Browsers) {
        Write-Host "`n  -- $($b.Name) --"
        $reg = Get-ItemProperty "$($b.Native)\$HostNm" -EA SilentlyContinue
        "     native host  : $(if ($reg.'(default)') { $reg.'(default)' } else { 'NOT registered' })"
        $al = Get-Item "$($b.Policy)\ExtensionInstallAllowlist" -EA SilentlyContinue
        $listed = $al -and ($al.GetValueNames() | ForEach-Object { $al.GetValue($_) }) -contains $info.ext_id
        "     allowlisted  : $listed"
    }
    Write-Host "`n  app serving now (open+unlocked): " -NoNewline
    $serving = & $Py -c "import sys; sys.path.insert(0,r'$Root\src'); import svipc; print(svipc.is_serving())" 2>$null
    Write-Host $serving
    Write-Host "`n  Load unpacked from  $Root\extension  in chrome://extensions and edge://extensions." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------- apply
function Invoke-Apply {
    if (-not $PSCmdlet.ShouldProcess('Chrome + Edge', 'register SecureVault autofill host and allowlist the extension')) { return }
    $info = Get-Info
    Write-Host "  extension id : $($info.ext_id)" -ForegroundColor Green
    Write-Host "  host manifest: $($info.hostmanifest)" -ForegroundColor DarkGray

    foreach ($b in $Browsers) {
        $key = "$($b.Native)\$HostNm"
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name '(default)' -PropertyType String `
            -Value $info.hostmanifest -Force | Out-Null
        Write-Host "  [$($b.Name)] native host registered (HKCU)" -ForegroundColor Green
    }

    if (Test-Elevated) {
        foreach ($b in $Browsers) {
            Add-Allowlist -PolicyKey $b.Policy -Id $info.ext_id
            Write-Host "  [$($b.Name)] extension allowlisted (HKLM policy)" -ForegroundColor Green
        }
    } else {
        Write-Host "`n  NOT ELEVATED - the policy allowlist was skipped. Without it, if the" -ForegroundColor Yellow
        Write-Host "  extension blocklist from Harden-Chrome.ps1 is active, the browsers will" -ForegroundColor Yellow
        Write-Host "  block this extension too. Re-run this script elevated to allowlist:" -ForegroundColor Yellow
        Write-Host "     $($info.ext_id)" -ForegroundColor Yellow
    }

    Write-Host "`n  NEXT (manual, one time):" -ForegroundColor Cyan
    Write-Host "   1. chrome://extensions and edge://extensions -> Developer mode ON"
    Write-Host "   2. Load unpacked -> $Root\extension"
    Write-Host "   3. verify the loaded ID is  $($info.ext_id)"
    Write-Host "   Open + unlock SecureVault.exe, then autofill is live."
}

# -------------------------------------------------------------------- revert
function Invoke-Revert {
    if (-not $PSCmdlet.ShouldProcess('Chrome + Edge', 'remove SecureVault autofill host and allowlist')) { return }
    $info = Get-Info
    foreach ($b in $Browsers) {
        $key = "$($b.Native)\$HostNm"
        if (Test-Path $key) { Remove-Item $key -Recurse -Force; Write-Host "  [$($b.Name)] native host unregistered" -ForegroundColor Green }
        if ($info.ext_id) {
            if (Test-Elevated) { Remove-Allowlist -PolicyKey $b.Policy -Id $info.ext_id; Write-Host "  [$($b.Name)] allowlist entry removed" -ForegroundColor Green }
            else { Write-Host "  [$($b.Name)] allowlist entry needs an elevated prompt to remove" -ForegroundColor Yellow }
        }
    }
    Write-Host "  Also remove the unpacked extension from chrome://extensions / edge://extensions." -ForegroundColor DarkGray
    Write-Host "  Keys under $Root\extension\_signing_key.pem were left in place." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------- main
if ($Apply -and $Revert) { throw "Pick one of -Apply or -Revert." }
if     ($Revert) { Invoke-Revert }
elseif ($Apply)  { Invoke-Apply }
else             { Show-Status }
