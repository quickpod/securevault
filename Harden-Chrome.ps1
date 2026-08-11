<#
    Harden-Chrome.ps1  -  Chrome enterprise-policy hardening for this laptop.

    Same shape as Fix-Gaps.ps1 / Set-EncryptedDns.ps1:
        (no switch)          read-only status, changes nothing
        -Apply               write policies, verify, auto-roll-back on failure
        -Revert              delete the policy keys outright -> Chrome defaults
        -ArmDeadMan <mins>   one-shot SYSTEM task that reverts unless -Disarm
        -Disarm              cancel the dead-man task
        -RemoveTrustWallet   SEPARATE, IRREVERSIBLE. See the warning below.

    Baseline captured 2026-08-06: HKLM\SOFTWARE\Policies\Google\Chrome and
    ...\Google\Update did NOT exist. That is the known-good default, so -Revert
    just deletes both keys and needs no backup file, no network, no downloads.

    -Apply needs elevation (writes HKLM). Status mode does not.

    WHY -RemoveTrustWallet IS SEPARATE
    Blocklisting an extension makes Chrome delete its local storage, and for a
    wallet that storage IS the encrypted vault. Recovery requires the seed
    phrase; -Revert cannot undo it - reverting only re-permits installation.
    So it never rides along with -Apply.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch] $Apply,
    [switch] $Revert,
    [switch] $RemoveTrustWallet,
    [int]    $ArmDeadMan = 0,
    [switch] $Disarm
)

$ErrorActionPreference = 'Stop'

$ChromeKey  = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$UpdateKey  = 'HKLM:\SOFTWARE\Policies\Google\Update'
$BlockKey   = "$ChromeKey\ExtensionInstallBlocklist"
$BackupDir  = 'C:\SecureVault\Backups'
$StageDir   = 'C:\SecureVault'          # C:, not S: - S may be unreadable when a task fires
$TaskName   = 'SecureVault-ChromeRevert'
$TrustWallet = 'egjidjbpglichdcondbcbdnbeeppgdph'

# ---------------------------------------------------------------- policy set
# Chosen 2026-08-06. DnsOverHttpsMode is deliberately "automatic", not
# "secure": this laptop lives on hotel captive portals and OS-level DoH
# (1.1.1.1 / 8.8.8.8, AutoUpgrade=True) already carries the lookups.
$Policies = [ordered]@{
    # --- Safe Browsing and downloads
    SafeBrowsingProtectionLevel               = @{ Type = 'DWord';  Value = 2 }          # 2 = Enhanced
    DownloadRestrictions                      = @{ Type = 'DWord';  Value = 2 }          # block potentially dangerous
    PromptForDownloadLocation                 = @{ Type = 'DWord';  Value = 1 }          # no silent drive-by saves

    # --- Transport. The hostile-network controls.
    HttpsOnlyMode                             = @{ Type = 'String'; Value = 'force_enabled' }
    SSLVersionMin                             = @{ Type = 'String'; Value = 'tls1.2' }
    DnsOverHttpsMode                          = @{ Type = 'String'; Value = 'automatic' }

    # --- Extension surface
    BlockExternalExtensions                   = @{ Type = 'DWord';  Value = 1 }

    # --- Content settings / hardware reach.  2 = block, 3 = ask
    BlockThirdPartyCookies                    = @{ Type = 'DWord';  Value = 1 }
    DefaultPopupsSetting                      = @{ Type = 'DWord';  Value = 2 }
    DefaultNotificationsSetting               = @{ Type = 'DWord';  Value = 2 }
    DefaultGeolocationSetting                 = @{ Type = 'DWord';  Value = 3 }
    DefaultSensorsSetting                     = @{ Type = 'DWord';  Value = 2 }
    DefaultWebUsbGuardSetting                 = @{ Type = 'DWord';  Value = 2 }
    DefaultSerialGuardSetting                 = @{ Type = 'DWord';  Value = 2 }
    DefaultWebBluetoothGuardSetting           = @{ Type = 'DWord';  Value = 2 }
    DefaultFileSystemReadGuardSetting         = @{ Type = 'DWord';  Value = 2 }
    DefaultFileSystemWriteGuardSetting        = @{ Type = 'DWord';  Value = 2 }

    # --- Remote reach. Mirrors the OS-level Cast/WFD rules already disabled.
    EnableMediaRouter                         = @{ Type = 'DWord';  Value = 0 }
    RemoteAccessHostFirewallTraversal         = @{ Type = 'DWord';  Value = 0 }
    RemoteAccessHostAllowRemoteAccessConnections = @{ Type = 'DWord'; Value = 0 }

    # --- Telemetry / Privacy Sandbox
    MetricsReportingEnabled                   = @{ Type = 'DWord';  Value = 0 }
    UrlKeyedAnonymizedDataCollectionEnabled   = @{ Type = 'DWord';  Value = 0 }
    PrivacySandboxAdTopicsEnabled             = @{ Type = 'DWord';  Value = 0 }
    PrivacySandboxSiteEnabledAdsEnabled       = @{ Type = 'DWord';  Value = 0 }
    PrivacySandboxAdMeasurementEnabled        = @{ Type = 'DWord';  Value = 0 }
    PrivacySandboxPromptEnabled               = @{ Type = 'DWord';  Value = 0 }
}

# Deliberately NOT set (asked and declined 2026-08-06): PasswordManagerEnabled,
# AutofillAddressEnabled, AutofillCreditCardEnabled. Root cause is the blank
# Windows account password, not Chrome.

$UpdatePolicies = [ordered]@{
    UpdateDefault                                   = @{ Type = 'DWord'; Value = 1 }  # always auto-update
    'Update{8A69D345-D564-463c-AFF1-A69D9E530F96}'  = @{ Type = 'DWord'; Value = 1 }  # ...specifically Chrome
    DisableAutoUpdateChecksCheckboxValue            = @{ Type = 'DWord'; Value = 0 }
}

# Extension blocklist. We deliberately do NOT use "*" here: a "*" blocklist
# also blocks UNPACKED (developer-mode) extensions even when their ID is on the
# allowlist, which prevented our own SecureVault Autofill extension from loading
# in Chrome (Edge, with no blocklist, worked fine). So we block Trust Wallet by
# ID and rely on BlockExternalExtensions=1 (set above) to stop sideloaded /
# registry-planted extensions. Net posture: no silent sideloading, Trust Wallet
# barred, but you (and only via the Web Store) can add extensions yourself.
# If you ever want the "*" lockdown back, force-install this extension as a
# signed .crx via ExtensionInstallForcelist instead of loading it unpacked.
$BlocklistEntries = [ordered]@{
    '1' = $TrustWallet   # explicit, so it shows by name in chrome://policy
}

# ------------------------------------------------------------------ helpers
function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PolicyValue {
    param($Key, $Name)
    if (-not (Test-Path $Key)) { return $null }
    $item = Get-Item $Key
    if ($item.GetValueNames() -notcontains $Name) { return $null }
    return $item.GetValue($Name)
}

function Set-PolicyValue {
    param($Key, $Name, $Type, $Value)
    # New-Item -Force on an EXISTING key deletes and recreates it empty. That is
    # what wiped Dnscache\ServiceDll on 2026-08-06. Only create when absent.
    if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
    New-ItemProperty -Path $Key -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Get-ChromeProfiles {
    $ud = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (-not (Test-Path $ud)) { return @() }
    return @(Get-ChildItem $ud -Directory -EA SilentlyContinue |
             Where-Object { Test-Path (Join-Path $_.FullName 'Preferences') })
}

function Get-InstalledExtensions {
    $out = @()
    foreach ($p in Get-ChromeProfiles) {
        $sp = Join-Path $p.FullName 'Secure Preferences'
        if (-not (Test-Path $sp)) { continue }
        try { $j = Get-Content $sp -Raw | ConvertFrom-Json } catch { continue }
        $settings = $j.extensions.settings
        if (-not $settings) { continue }
        foreach ($id in $settings.PSObject.Properties.Name) {
            $e = $settings.$id
            $out += [pscustomobject]@{
                Profile  = $p.Name
                Id       = $id
                Name     = $(if ($e.manifest.name) { $e.manifest.name } else { '(no manifest)' })
                Location = $e.location      # 5/10 = built-in component, 1 = user-installed
                Store    = $e.from_webstore
            }
        }
    }
    return $out
}

# -------------------------------------------------------------------- status
function Show-Status {
    Write-Host "==== CHROME ====" -ForegroundColor Cyan
    $exe = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    if (Test-Path $exe) { "  version : $((Get-Item $exe).VersionInfo.ProductVersion)" }
    else { "  chrome.exe not found in Program Files" }
    $running = @(Get-Process chrome -EA SilentlyContinue).Count
    "  running : $running processes"
    if ($running) {
        Write-Host "  NOTE: policy changes need a full Chrome restart to take effect." -ForegroundColor Yellow
    }

    Write-Host "`n==== POLICY STATE ====" -ForegroundColor Cyan
    if (-not (Test-Path $ChromeKey)) {
        Write-Host "  NO POLICIES APPLIED - every setting is user- and malware-changeable." -ForegroundColor Yellow
    }
    $applied = 0
    foreach ($name in $Policies.Keys) {
        $want = $Policies[$name].Value
        $have = Get-PolicyValue -Key $ChromeKey -Name $name
        if ($null -eq $have)      { $mark = 'MISSING '; $col = 'Red' }
        elseif ("$have" -eq "$want") { $mark = 'ok      '; $col = 'Green'; $applied++ }
        else                      { $mark = 'DRIFT   '; $col = 'Red' }
        Write-Host ("  {0} {1,-44} want={2,-14} have={3}" -f $mark, $name, $want, $have) -ForegroundColor $col
    }
    "  -> $applied/$($Policies.Count) Chrome policies in place"

    Write-Host "`n  -- extension blocklist --"
    foreach ($k in $BlocklistEntries.Keys) {
        $have = Get-PolicyValue -Key $BlockKey -Name $k
        "     [{0}] want='{1}'  have='{2}'" -f $k, $BlocklistEntries[$k], $have
    }

    Write-Host "`n  -- updater --"
    foreach ($name in $UpdatePolicies.Keys) {
        $have = Get-PolicyValue -Key $UpdateKey -Name $name
        "     {0,-48} want={1}  have={2}" -f $name, $UpdatePolicies[$name].Value, $have
    }

    Write-Host "`n==== EXTENSIONS PRESENT ====" -ForegroundColor Cyan
    $exts = Get-InstalledExtensions
    if (-not $exts) { "  none found" }
    foreach ($e in $exts | Sort-Object Profile, Name) {
        # location 5 and 10 are Chrome's own component extensions; policy does
        # not touch them and their presence is expected. Entries with no
        # location at all are bare {"lastpingday"} metadata stubs - nothing is
        # installed, so they are not a surface either.
        if ($null -eq $e.Location -or '' -eq "$($e.Location)") { $kind = 'stub'; $col = 'DarkGray' }
        elseif ($e.Location -in 5, 10)                         { $kind = 'component'; $col = 'Gray' }
        else                                                   { $kind = 'USER-INSTALLED'; $col = 'Yellow' }
        Write-Host ("  {0,-10} {1,-26} {2,-16} {3}" -f $e.Profile, $e.Name, $kind, $e.Id) -ForegroundColor $col
    }
    if ($exts.Id -contains $TrustWallet) {
        Write-Host "`n  Trust Wallet still installed. Run -RemoveTrustWallet (irreversible)." -ForegroundColor Yellow
    }

    Write-Host "`n==== SAFETY NETS ====" -ForegroundColor Cyan
    $t = Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
    if ($t) {
        $when = (Get-ScheduledTaskInfo $t).NextRunTime
        Write-Host "  ARMED: $TaskName reverts at $when. Run -Disarm to keep the policies." -ForegroundColor Yellow
    } else { "  no dead-man task armed" }
    "`n  Ground truth is chrome://policy - check there after any change."
}

# --------------------------------------------------------------------- apply
function Invoke-Apply {
    if (-not (Test-Elevated)) { throw "-Apply writes HKLM and needs an elevated prompt." }
    if (-not $PSCmdlet.ShouldProcess('HKLM\SOFTWARE\Policies\Google', 'Apply Chrome hardening policies')) { return }

    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }

    # Fidelity only. -Revert never reads this: baseline is "keys absent".
    $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = Join-Path $BackupDir "chrome-policy-pre-$stamp.json"
    $prior  = @{
        capturedAt      = (Get-Date).ToString('o')
        chromeKeyExisted = Test-Path $ChromeKey
        updateKeyExisted = Test-Path $UpdateKey
        chromeValues    = @{}
        updateValues    = @{}
    }
    if (Test-Path $ChromeKey) {
        $i = Get-Item $ChromeKey
        foreach ($n in $i.GetValueNames()) { $prior.chromeValues[$n] = $i.GetValue($n) }
    }
    if (Test-Path $UpdateKey) {
        $i = Get-Item $UpdateKey
        foreach ($n in $i.GetValueNames()) { $prior.updateValues[$n] = $i.GetValue($n) }
    }
    $prior | ConvertTo-Json -Depth 5 | Out-File $backup -Encoding utf8
    Write-Host "  prior state -> $backup" -ForegroundColor DarkGray

    try {
        foreach ($name in $Policies.Keys) {
            Set-PolicyValue -Key $ChromeKey -Name $name -Type $Policies[$name].Type -Value $Policies[$name].Value
        }
        foreach ($k in $BlocklistEntries.Keys) {
            Set-PolicyValue -Key $BlockKey -Name $k -Type 'String' -Value $BlocklistEntries[$k]
        }
        foreach ($name in $UpdatePolicies.Keys) {
            Set-PolicyValue -Key $UpdateKey -Name $name -Type $UpdatePolicies[$name].Type -Value $UpdatePolicies[$name].Value
        }

        # Verify before declaring success.
        $bad = @()
        foreach ($name in $Policies.Keys) {
            $have = Get-PolicyValue -Key $ChromeKey -Name $name
            if ("$have" -ne "$($Policies[$name].Value)") { $bad += "$name (have='$have')" }
        }
        foreach ($k in $BlocklistEntries.Keys) {
            $have = Get-PolicyValue -Key $BlockKey -Name $k
            if ("$have" -ne "$($BlocklistEntries[$k])") { $bad += "blocklist[$k] (have='$have')" }
        }
        if ($bad.Count) { throw "verification failed: $($bad -join '; ')" }
    }
    catch {
        Write-Host "  APPLY FAILED - rolling back. $($_.Exception.Message)" -ForegroundColor Red
        Invoke-Revert -Silent
        throw
    }

    Write-Host "  applied and verified: $($Policies.Count) policies + blocklist + updater." -ForegroundColor Green
    Write-Host "  RESTART CHROME COMPLETELY, then confirm at chrome://policy." -ForegroundColor Yellow
    Write-Host "  Blocklisting removes Google Docs Offline and ColorPick Eyedropper too." -ForegroundColor Yellow
}

# -------------------------------------------------------------------- revert
function Invoke-Revert {
    param([switch] $Silent)
    if (-not (Test-Elevated)) { throw "-Revert writes HKLM and needs an elevated prompt." }
    if (-not $Silent) {
        if (-not $PSCmdlet.ShouldProcess('HKLM\SOFTWARE\Policies\Google', 'Remove Chrome policy keys')) { return }
    }
    # Baseline was "absent". Deleting is the whole revert - no state file, no
    # network. Worst case Chrome returns to stock defaults, which is safe.
    foreach ($k in $ChromeKey, $UpdateKey) {
        if (Test-Path $k) {
            Remove-Item $k -Recurse -Force -Confirm:$false
            Write-Host "  removed $k" -ForegroundColor Green
        } else {
            Write-Host "  $k already absent" -ForegroundColor DarkGray
        }
    }
    $g = 'HKLM:\SOFTWARE\Policies\Google'
    if ((Test-Path $g) -and -not (Get-ChildItem $g -EA SilentlyContinue) -and
        -not (Get-Item $g).GetValueNames()) {
        Remove-Item $g -Force -Confirm:$false
    }
    if (-not $Silent) { Write-Host "  Chrome back to stock defaults. Restart Chrome." -ForegroundColor Green }
}

# ------------------------------------------------------------ trust wallet
function Remove-TrustWalletExtension {
    if (-not $PSCmdlet.ShouldProcess("Trust Wallet ($TrustWallet)", 'PERMANENTLY delete extension and its encrypted vault')) { return }

    Write-Host @"

  ------------------------------------------------------------------
  IRREVERSIBLE. This deletes Trust Wallet's extension storage, which
  is the encrypted wallet itself. The ONLY way back is your seed
  phrase. -Revert cannot undo this; it only re-permits installation.
  ------------------------------------------------------------------
"@ -ForegroundColor Red

    $ans = Read-Host "  Type the words  I HAVE MY SEED  to proceed"
    if ($ans -ne 'I HAVE MY SEED') { Write-Host "  aborted, nothing changed." -ForegroundColor Yellow; return }

    if (@(Get-Process chrome -EA SilentlyContinue).Count) {
        Write-Host "  Close Chrome completely first - it rewrites these files on exit." -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $removed = 0
    foreach ($p in Get-ChromeProfiles) {
        $extDir = Join-Path $p.FullName "Extensions\$TrustWallet"
        if (-not (Test-Path $extDir)) { continue }
        # Cold copy of the encrypted vault before deleting. Still needs the seed
        # to be useful, but it beats having nothing.
        $dest = Join-Path $BackupDir "TrustWallet-$($p.Name)-$stamp"
        Copy-Item $extDir $dest -Recurse -Force
        Write-Host "  archived $extDir -> $dest" -ForegroundColor DarkGray
        Remove-Item $extDir -Recurse -Force -Confirm:$false
        $removed++
    }
    foreach ($p in Get-ChromeProfiles) {
        foreach ($sub in 'Local Extension Settings', 'Sync Extension Settings', 'IndexedDB', 'Local Storage\leveldb') {
            $d = Join-Path $p.FullName "$sub\$TrustWallet"
            if (Test-Path $d) {
                $dest = Join-Path $BackupDir "TrustWallet-$($p.Name)-$($sub -replace '\\','_')-$stamp"
                Copy-Item $d $dest -Recurse -Force
                Remove-Item $d -Recurse -Force -Confirm:$false
                Write-Host "  removed $d (archived)" -ForegroundColor DarkGray
            }
        }
    }
    if ($removed) { Write-Host "  Trust Wallet removed from $removed profile(s)." -ForegroundColor Green }
    else { Write-Host "  Trust Wallet extension directory not found - may already be gone." -ForegroundColor Yellow }
    Write-Host "  Archives are in $BackupDir - move them offline or shred them." -ForegroundColor Yellow
}

# ----------------------------------------------------------- dead-man switch
function Enable-DeadMan {
    param([int] $Minutes)
    if (-not (Test-Elevated)) { throw "-ArmDeadMan needs an elevated prompt." }
    if (-not (Test-Path $StageDir)) { New-Item -ItemType Directory -Path $StageDir -Force | Out-Null }
    # Staged on C: deliberately - S: may not be readable when the task fires.
    $stage = Join-Path $StageDir 'chrome-deadman-revert.ps1'
    @"
Remove-Item 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Recurse -Force -EA SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Policies\Google\Update' -Recurse -Force -EA SilentlyContinue
Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false -EA SilentlyContinue
"@ | Out-File $stage -Encoding utf8

    $when   = (Get-Date).AddMinutes($Minutes)
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
                -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$stage`""
    $trig   = New-ScheduledTaskTrigger -Once -At $when
    $princ  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trig -Principal $princ -Force | Out-Null
    Write-Host "  ARMED: reverts at $when unless you run -Disarm." -ForegroundColor Yellow
}

function Disable-DeadMan {
    if (-not (Test-Elevated)) { throw "-Disarm needs an elevated prompt." }
    if (Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "  disarmed - policies will stay." -ForegroundColor Green
    } else { Write-Host "  no dead-man task was armed." -ForegroundColor DarkGray }
    $stage = Join-Path $StageDir 'chrome-deadman-revert.ps1'
    if (Test-Path $stage) { Remove-Item $stage -Force -Confirm:$false }
}

# ---------------------------------------------------------------------- main
if ($Apply -and $Revert) { throw "Pick one of -Apply or -Revert." }

if     ($Disarm)            { Disable-DeadMan }
elseif ($RemoveTrustWallet) { Remove-TrustWalletExtension }
elseif ($Revert)            { Invoke-Revert }
elseif ($Apply)             { Invoke-Apply; if ($ArmDeadMan -gt 0) { Enable-DeadMan -Minutes $ArmDeadMan } }
elseif ($ArmDeadMan -gt 0)  { Enable-DeadMan -Minutes $ArmDeadMan }
else                        { Show-Status }
