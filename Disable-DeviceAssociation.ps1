<#
    Disable-DeviceAssociation.ps1  -  stop dasHost.exe holding UDP 3702.

    RUN IN AN ELEVATED (Administrator) PowerShell.

    WHAT AND WHY
    DeviceAssociationService (DAS) is a svchost service that spawns a separate
    child process, dasHost.exe - the Device Association Framework Provider Host.
    dasHost is what actually opens the sockets:

        UDP :::3702  +  UDP 0.0.0.0:3702   WS-Discovery, fixed multicast port
        UDP 0.0.0.0:5xxxx + :::5xxxx       its two ephemeral WSD reply sockets

    dasHost.exe is a CHILD PROCESS, not a registered service, so a port audit
    cannot map those listeners to a service name and cannot read the image path
    without elevation. That is why it audits as an unattributed world-listening
    process. It is signed Microsoft code.

    ============================================================================
    MEASURED 2026-08-08 - READ THIS BEFORE CHANGING THE SCRIPT
    ============================================================================
    DO NOT STOP THIS SERVICE. Stopping it is what undoes the change.

    Something on this machine watches DAS and repairs it the moment it actually
    stops - it rewrites Start back to 2 (auto) and restarts the service within
    about one second. Isolated with a two-phase A/B test, HP Print and Scan
    Doctor's service running in both phases so it was not the variable:

      PHASE A   Set-Service -StartupType Disabled, no stop.
                Start stayed 4 for the full 12s watch.            HOLDS.
      PHASE B   Same, then 'sc stop'.
                Start flipped 4 -> 2 within 1s; service back to
                Running by t+6s.                                  REVERTED.

    Confirmed independently in the SCM log (event 7040): every "auto start to
    disabled" is followed by a "disabled to auto start" one second later, and
    only ever after a stop was issued. The repairer was NOT identified - it is
    not Group Policy (no MDM enrolled, and GP does not react in one second),
    not the service's own failure actions (those are RESTART at 60s/120s and do
    not rewrite start type), and not HP. If you need to know what it is, audit
    SetValue on the service key and read event 4657 for the writing PID.

    Two corollaries:
      - -Level Manual is useless. Trigger-start plus the repairer means it is
        running again within a second. An earlier version of this script
        offered it; it did not work.
      - An apply that stops the service defeats itself. The earlier version did
        exactly that: it set Disabled correctly, then stopped the service,
        which tripped the repairer and reverted its own change. Do not
        reintroduce a stop here.

    So this script sets Start=Disabled and leaves the running instance alone.
    THE LISTENER DOES NOT GO AWAY UNTIL YOU REBOOT. dasHost keeps holding 3702
    for the rest of this session; at next boot DAS never starts and the four
    audit lines are gone. Re-run with no switches after the reboot to confirm -
    and confirm it, because whether the repairer also fires at boot has not
    been tested.

    COST
    Pairing NEW devices stops working until you -Revert: Bluetooth pairing, WSD
    printer/scanner setup, Miracast, Phone Link association. ALREADY-PAIRED
    devices are unaffected - bthserv handles the connection, DAS only handles
    the association. Printing to an already-installed printer is unaffected;
    ADDING one by WSD discovery is not.

    HOW MUCH THIS BUYS - be honest about it
    With DefaultInboundAction=Block on all three profiles and no allow rule
    covering 3702, this listener is ALREADY unreachable from the network. This
    is attack-surface reduction and audit hygiene - removing a world-bound
    socket and four WARN lines - not the closing of a live hole.

    SCOPE - what this does NOT touch, deliberately:
      services.exe TCP 49670   SCM's RPC endpoint
      wininit.exe  TCP 49665   Windows Init's RPC endpoint
    Dynamic RPC endpoints that cannot be unbound without breaking the machine,
    already unreachable behind the same inbound block, and flagged by the audit
    for the same elevation reason. Leave them.

    NO DEAD-MAN SWITCH, deliberately. This cannot lock you out of anything: it
    removes a background listener, never blocks an action, and -Revert needs no
    network, no download and no state file.

    MODES
      (no switches)   Read-only status.
      -Apply          Set DAS to Disabled. Does NOT stop it. Saves prior state,
                      confirms the value stuck, rolls back if it did not.
      -Revert         Set DAS back to Automatic and start it. Takes effect
                      immediately - no reboot needed to get pairing back.
      -WhatIf         Show what would change, change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $Apply,
    [switch] $Revert
)

$ErrorActionPreference = 'Stop'
$BackupDir    = 'C:\SecureVault\Backups'
$SvcName      = 'DeviceAssociationService'
$WsdPort      = 3702
$DefaultStart = 'Automatic'   # known-good fallback, never depended on a file
$RegPath      = "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName"

function Get-TriggerCount {
    @(& sc.exe qtriggerinfo $SvcName 2>&1 | Select-String 'START SERVICE').Count
}

function Get-DasState {
    $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if (-not $svc) { throw "$SvcName not present on this machine." }

    # Registry Start is authoritative - Get-Service can lag sc config.
    $start = (Get-ItemProperty $RegPath).Start
    $startName = switch ($start) { 2 {'Automatic'} 3 {'Manual'} 4 {'Disabled'} default {"Start=$start"} }

    $procs = @(Get-Process -Name 'dasHost' -ErrorAction SilentlyContinue)
    $udp   = @(Get-NetUDPEndpoint -LocalPort $WsdPort -ErrorAction SilentlyContinue)
    $eph   = @()
    if ($procs) {
        $ids = $procs.Id
        $eph = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
                 Where-Object { $_.OwningProcess -in $ids -and $_.LocalPort -ne $WsdPort })
    }

    [pscustomobject]@{
        StartType      = $startName
        StartValue     = $start
        State          = $svc.Status.ToString()
        DasHostPids    = $procs.Id
        WsdEndpoints   = @($udp | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" })
        EphemeralPorts = @($eph | ForEach-Object { $_.LocalPort } | Sort-Object -Unique)
        TriggerCount   = (Get-TriggerCount)
    }
}

function Show-Status {
    param($S)
    ''
    "  Service       : $SvcName ($($S.State), $($S.StartType))"
    "  Start triggers: $($S.TriggerCount) registered"
    if ($S.DasHostPids) { "  dasHost.exe   : running, PID $($S.DasHostPids -join ', ')" }
    else                { '  dasHost.exe   : not running' }
    if ($S.WsdEndpoints) { "  UDP $WsdPort     : $($S.WsdEndpoints -join '  ')" }
    else                 { "  UDP $WsdPort     : not bound" }
    if ($S.EphemeralPorts) { "  WSD ephemeral : $($S.EphemeralPorts -join ', ')" }
    ''

    if ($S.StartType -eq 'Disabled' -and -not $S.DasHostPids) {
        'CLOSED. Disabled and not running - this is the state you want.'
    }
    elseif ($S.StartType -eq 'Disabled') {
        'APPLIED BUT PENDING REBOOT. Start type is Disabled, so DAS will not come'
        'back at next boot, but the current instance is still holding the port.'
        'Expected. Re-run this after the reboot to confirm it stayed Disabled.'
    }
    else {
        "dasHost is present and DAS is $($S.StartType)."
        if ($S.WsdEndpoints.Count -eq 0) {
            "(3702 reads unbound right now - it re-binds a few seconds after each"
            " restart, so judge by dasHost, not by the port alone.)"
        }
    }
    ''
}

function Assert-Admin {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
                  [Security.Principal.WindowsIdentity]::GetCurrent())
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $WhatIfPreference) {
        throw 'Not elevated. Changing a service start type needs Administrator. Re-run from an elevated PowerShell.'
    }
    if (-not $isAdmin) { 'NOTE: not elevated - -WhatIf only. A real run needs Administrator.' }
}

# ---------------------------------------------------------------- status ----
$before = Get-DasState

if (-not $Apply -and -not $Revert) {
    Show-Status -S $before
    if ($before.StartType -ne 'Disabled') {
        'Run with -Apply (elevated) to close it, then reboot.'
        'See the header for what that costs you (pairing NEW devices).'
        ''
    }
    return
}
if ($Apply -and $Revert) { throw 'Pass -Apply or -Revert, not both.' }
Assert-Admin

# ----------------------------------------------------------------- apply ----
if ($Apply) {
    if ($before.StartType -eq 'Disabled') {
        'Nothing to do - DAS is already Disabled.'
        Show-Status -S $before
        return
    }

    if (-not (Test-Path $BackupDir)) { $null = New-Item -ItemType Directory -Path $BackupDir -Force }
    $stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
    $statePath = Join-Path $BackupDir "das-startup-$stamp.json"

    if ($PSCmdlet.ShouldProcess($statePath, 'Save prior DAS state')) {
        $before | ConvertTo-Json -Depth 4 | Out-File -FilePath $statePath -Encoding utf8
        "Prior state saved: $statePath"
    }

    if (-not $PSCmdlet.ShouldProcess($SvcName, 'StartupType = Disabled (service left running)')) { return }

    try {
        Set-Service -Name $SvcName -StartupType Disabled
        '  OK       start type -> Disabled  (service deliberately NOT stopped)'
    }
    catch {
        throw "Could not set start type: $($_.Exception.Message). Nothing changed."
    }

    if ($WhatIfPreference) { return }

    # The repairer acts within ~1s. Watch longer than that before believing it.
    ''
    'Watching 10s to confirm the value is not rewritten...'
    foreach ($i in 1..10) {
        Start-Sleep -Seconds 1
        $now = (Get-ItemProperty $RegPath).Start
        if ($now -ne 4) {
            "  t+${i}s  Start rewritten to $now - the repairer fired."
            Set-Service -Name $SvcName -StartupType $DefaultStart
            throw "Start type did not stick (rewritten to $now). Restored $DefaultStart. Nothing gained; nothing broken."
        }
    }
    '  held for 10s.'

    $after = Get-DasState
    if ($after.TriggerCount -lt $before.TriggerCount) {
        '  WARNING  start triggers were lost - -Revert would not restore pairing. Rolling back.'
        Set-Service -Name $SvcName -StartupType $DefaultStart
        Start-Service -Name $SvcName -ErrorAction SilentlyContinue
        throw "Trigger count fell from $($before.TriggerCount) to $($after.TriggerCount). Rolled back."
    }

    Show-Status -S $after
    "Triggers still registered ($($after.TriggerCount)) - -Revert restores pairing fully."
    'REBOOT to actually release UDP 3702, then re-run this script with no switches.'
    "Revert with:  .\Disable-DeviceAssociation.ps1 -Revert"
    return
}

# ---------------------------------------------------------------- revert ----
if ($Revert) {
    $want = $DefaultStart
    $usedState = $false
    if (Test-Path $BackupDir) {
        $newest = Get-ChildItem -Path $BackupDir -Filter 'das-startup-*.json' -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest) {
            try {
                $state = Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json
                # Never restore INTO a closed state - that would make -Revert a no-op.
                if ($state.StartType -in 'Automatic','Manual') {
                    $want = $state.StartType
                    $usedState = $true
                    "Restoring the start type recorded in $($newest.Name): $want."
                }
            } catch { }
        }
    }
    if (-not $usedState) { "No usable saved state. Falling back to the known-good default: $DefaultStart + running." }

    if ($PSCmdlet.ShouldProcess($SvcName, "StartupType = $want")) {
        Set-Service -Name $SvcName -StartupType $want
        "  OK       start type -> $want"
    }
    if ($PSCmdlet.ShouldProcess($SvcName, 'Start service')) {
        Start-Service -Name $SvcName -ErrorAction SilentlyContinue
        '  OK       service started'
    }

    if ($WhatIfPreference) { return }

    ''
    'Pairing is available again immediately - no reboot needed.'
    Show-Status -S (Get-DasState)
    return
}
