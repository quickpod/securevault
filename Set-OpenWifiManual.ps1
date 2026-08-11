<#
    Set-OpenWifiManual.ps1  -  stop the laptop silently joining OPEN Wi-Fi.

    RUN IN AN ELEVATED (Administrator) PowerShell.
    'netsh wlan set profileparameter' on an all-user profile needs admin;
    unelevated it fails with "The parameter is incorrect" / access denied.

    WHAT AND WHY
    Every saved profile whose Authentication is "Open" is set to
    connectionmode=MANUAL. The profile is KEPT - the network still appears in
    the list and one click still joins it. Only the silent auto-join stops.

    The exposure this closes is the evil twin. An open profile set to auto
    means the radio associates with ANY access point broadcasting that SSID,
    with no key to prove it is the real one. "Hilton Honors" in an airport is
    indistinguishable from "Hilton Honors" in a hotel. This machine travels,
    so those profiles are worth keeping - just not worth joining unattended.

    WPA2/WPA3 profiles are left alone: the PSK authenticates the AP, so
    auto-connect there is not the same risk. Use -All to include them anyway.

    NO DEAD-MAN SWITCH, deliberately. Unlike the DNS and firewall work, this
    change cannot lock you out of anything - it removes an automatic action,
    it never blocks a manual one. Worst case you tap the SSID yourself.

    MODES
      (no switches)   Read-only status: every profile, its auth, its mode,
                      and which ones this script would change.
      -Apply          Set open profiles to manual. Saves prior state, verifies
                      each one afterwards, rolls back automatically on failure.
      -Revert         Set open profiles back to automatic. Uses the newest
                      saved state if one is there; otherwise falls back to the
                      known-good default (every Open profile -> automatic).
                      Needs no network and no state file.

    OPTIONS
      -All            Operate on every profile, not just the open ones.
      -Name <list>    Operate on named profiles only.
      -WhatIf         Show what would change, change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $Apply,
    [switch] $Revert,
    [switch] $All,
    [string[]] $Name
)

$ErrorActionPreference = 'Stop'
$BackupDir = 'C:\SecureVault\Backups'

function Get-WifiProfile {
    $names = (netsh wlan show profiles) |
        Select-String 'All User Profile\s*:\s*(.+)$' |
        ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }

    foreach ($n in $names) {
        $out  = netsh wlan show profile name="$n"
        $mode = ($out | Select-String 'Connection mode\s*:\s*(.+)$').Matches.Groups[1].Value.Trim()
        $auth = ($out | Select-String 'Authentication\s*:\s*(.+)$' | Select-Object -First 1).Matches.Groups[1].Value.Trim()
        [pscustomobject]@{
            Name   = $n
            Auth   = $auth
            Mode   = $(if ($mode -match 'auto') { 'auto' } else { 'manual' })
            IsOpen = ($auth -eq 'Open')
        }
    }
}

function Select-Target {
    param($Profiles)
    if ($Name)     { return $Profiles | Where-Object { $_.Name -in $Name } }
    if ($All)      { return $Profiles }
    return $Profiles | Where-Object { $_.IsOpen }
}

function Set-Mode {
    # Returns $true if the profile is at $Want after the call.
    param([string] $ProfileName, [ValidateSet('auto','manual')] [string] $Want)

    $null = netsh wlan set profileparameter name="$ProfileName" connectionmode=$Want 2>&1
    $out  = netsh wlan show profile name="$ProfileName"
    $mode = ($out | Select-String 'Connection mode\s*:\s*(.+)$').Matches.Groups[1].Value.Trim()
    if ($Want -eq 'auto') { return $mode -match 'auto' }
    return $mode -notmatch 'auto'
}

function Show-Status {
    param($Profiles, $Targets)

    ''
    '{0,-34} | {1,-14} | {2}' -f 'PROFILE', 'AUTH', 'MODE'
    '{0,-34} | {1,-14} | {2}' -f ('-' * 34), ('-' * 14), ('-' * 8)
    foreach ($p in $Profiles) {
        $flag = if ($p.IsOpen -and $p.Mode -eq 'auto') { '   <-- OPEN + AUTO' } else { '' }
        ('{0,-34} | {1,-14} | {2}{3}' -f $p.Name, $p.Auth, $p.Mode, $flag)
    }
    ''
    $exposed = @($Profiles | Where-Object { $_.IsOpen -and $_.Mode -eq 'auto' })
    if ($exposed.Count -eq 0) {
        'No open network is set to auto-connect. This is the state you want.'
    } else {
        "$($exposed.Count) open network(s) will be joined silently. Run with -Apply (elevated) to stop that."
    }
    if ($Targets) { "In scope for this run: $($Targets.Count) profile(s)." }
    ''
}

# ---------------------------------------------------------------- status ----
$profiles = @(Get-WifiProfile)
$targets  = @(Select-Target $profiles)

if (-not $Apply -and -not $Revert) {
    Show-Status -Profiles $profiles -Targets $null
    return
}

if ($Apply -and $Revert) { throw 'Pass -Apply or -Revert, not both.' }

$isAdmin = (New-Object Security.Principal.WindowsPrincipal(
              [Security.Principal.WindowsIdentity]::GetCurrent())
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
    throw 'Not elevated. netsh wlan set profileparameter needs Administrator. Re-run from an elevated PowerShell.'
}
if (-not $isAdmin) { 'NOTE: not elevated - -WhatIf only. A real run needs Administrator.' }

# ----------------------------------------------------------------- apply ----
if ($Apply) {
    $todo = @($targets | Where-Object { $_.Mode -eq 'auto' })
    if ($todo.Count -eq 0) { 'Nothing to do - no profile in scope is set to auto-connect.'; return }

    if (-not (Test-Path $BackupDir)) { $null = New-Item -ItemType Directory -Path $BackupDir }
    $stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
    $statePath = Join-Path $BackupDir "wifi-connectionmode-$stamp.json"

    if ($PSCmdlet.ShouldProcess($statePath, 'Save prior connection modes')) {
        $profiles | Select-Object Name, Auth, Mode | ConvertTo-Json |
            Out-File -FilePath $statePath -Encoding utf8
        "Prior state saved: $statePath"
    }

    $done = @()
    foreach ($p in $todo) {
        if (-not $PSCmdlet.ShouldProcess($p.Name, 'connectionmode=manual')) { continue }
        if (Set-Mode -ProfileName $p.Name -Want 'manual') {
            "  OK       $($p.Name)"
            $done += $p
        } else {
            "  FAILED   $($p.Name) - rolling back this run"
            foreach ($d in $done) { $null = Set-Mode -ProfileName $d.Name -Want 'auto' }
            throw "Could not set '$($p.Name)' to manual. Rolled back $($done.Count) profile(s); nothing changed."
        }
    }

    ''
    'Verifying against a fresh read of the profile store...'
    Show-Status -Profiles @(Get-WifiProfile) -Targets $null
    "Revert with:  .\Set-OpenWifiManual.ps1 -Revert"
    return
}

# ---------------------------------------------------------------- revert ----
if ($Revert) {
    # Fidelity path: newest saved state. Never depended on.
    $state = $null
    if (Test-Path $BackupDir) {
        $newest = Get-ChildItem -Path $BackupDir -Filter 'wifi-connectionmode-*.json' -EA SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest) {
            try   { $state = Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json
                    "Restoring the modes recorded in $($newest.Name)." }
            catch { $state = $null }
        }
    }
    if (-not $state) { 'No usable saved state. Falling back to the default: every profile in scope -> automatic.' }

    foreach ($p in $targets) {
        $want = 'auto'
        if ($state) {
            $prior = $state | Where-Object { $_.Name -eq $p.Name } | Select-Object -First 1
            if ($prior) { $want = $prior.Mode }
        }
        if ($p.Mode -eq $want) { "  skip     $($p.Name) (already $want)"; continue }
        if (-not $PSCmdlet.ShouldProcess($p.Name, "connectionmode=$want")) { continue }
        if (Set-Mode -ProfileName $p.Name -Want $want) { "  OK       $($p.Name) -> $want" }
        else { "  FAILED   $($p.Name) -> $want" }
    }

    ''
    Show-Status -Profiles @(Get-WifiProfile) -Targets $null
    return
}
