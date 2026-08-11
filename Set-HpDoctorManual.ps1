<#
    Set-HpDoctorManual.ps1  -  stop HP Print and Scan Doctor running at idle.

    RUN IN AN ELEVATED (Administrator) PowerShell.

    WHAT AND WHY
    HPPrintScanDoctorService is the only non-Microsoft service running on this
    machine. It is AUTO_START, LocalSystem, own process, from
    C:\Program Files\HPPrintScanDoctor\HPPrintScanDoctorService.exe (signed,
    HP Inc.). It is the backend for HP's Print and Scan Doctor troubleshooter -
    a diagnostic tool you invoke when printing breaks. It does not need to run
    continuously, and it holds no listening sockets, so this is idle-footprint
    and least-privilege housekeeping rather than closing an exposure.

    MEASURED 2026-08-08 - why this one is straightforward, unlike DAS:
      - NO start triggers registered. Manual therefore actually means manual;
        contrast DeviceAssociationService, which has five RPC triggers and is
        restarted within a second (see Disable-DeviceAssociation.ps1).
      - No dependent services, no services depended on.
      - Nothing guards it. An A/B test on 2026-08-08 stopped this service to
        see whether it was what re-enabled DAS; it was not, and stopping it
        caused nothing else to react.

    ONE THING TO WATCH: failure actions are RESTART at 5000ms, twice, with an
    86400s reset period. Those fire on UNEXPECTED termination, not on a clean
    SCM stop, so Stop-Service is safe - but this script still soaks for 15s,
    past both restart delays, before it will report success.

    NOT TOUCHED by this script - HP also has two scheduled tasks that run
    HPPrinterHealthMonitor.exe independently of the service:
        \HP\HP Print Scan Doctor\Printer Health Monitor
        \HP\HP Print Scan Doctor\Printer Health Monitor Logon
    Setting the service to Manual does NOT disable those. Disable them
    separately if you want HP fully quiet at idle.

    EFFECT: HP Print and Scan Doctor still works. Launching the troubleshooter
    starts the service on demand; Windows starts a Manual service when a client
    opens it. You may see a UAC prompt you did not see before.

    NO DEAD-MAN SWITCH, deliberately - this cannot lock you out of anything and
    -Revert needs no network, no download and no state file.

    MODES
      (no switches)   Read-only status.
      -Apply          Set Manual and stop. Saves prior state, soaks 15s, rolls
                      back automatically if it does not stay stopped.
      -Revert         Set back to Automatic and start. Immediate, no reboot.
      -WhatIf         Show what would change, change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $Apply,
    [switch] $Revert
)

$ErrorActionPreference = 'Stop'
$BackupDir    = 'C:\SecureVault\Backups'
$SvcName      = 'HPPrintScanDoctorService'
$DefaultStart = 'Automatic'   # known-good fallback, never depended on a file
$RegPath      = "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName"

function Get-HpState {
    $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if (-not $svc) { throw "$SvcName not present on this machine." }
    $start = (Get-ItemProperty $RegPath).Start
    $startName = switch ($start) { 2 {'Automatic'} 3 {'Manual'} 4 {'Disabled'} default {"Start=$start"} }
    $cim = Get-CimInstance Win32_Service -Filter "Name='$SvcName'"
    [pscustomobject]@{
        StartType  = $startName
        StartValue = $start
        State      = $svc.Status.ToString()
        ProcessId  = $cim.ProcessId
        Triggers   = @(& sc.exe qtriggerinfo $SvcName 2>&1 | Select-String 'START SERVICE').Count
    }
}

function Show-Status {
    param($S)
    ''
    "  Service    : $SvcName ($($S.State), $($S.StartType))"
    "  Triggers   : $($S.Triggers)  (0 means Manual genuinely holds)"
    "  PID        : $(if ($S.ProcessId -gt 0) { $S.ProcessId } else { '-' })"
    ''
    if ($S.StartType -eq 'Manual' -and $S.State -eq 'Stopped') {
        'Stopped and Manual - this is the state you want. The troubleshooter still'
        'starts it on demand.'
    } elseif ($S.State -eq 'Running') {
        "Running at idle. Run with -Apply (elevated) to stop that."
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

function Restore-Default {
    Set-Service -Name $SvcName -StartupType $DefaultStart
    Start-Service -Name $SvcName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- status ----
$before = Get-HpState

if (-not $Apply -and -not $Revert) { Show-Status -S $before; return }
if ($Apply -and $Revert) { throw 'Pass -Apply or -Revert, not both.' }
Assert-Admin

# ----------------------------------------------------------------- apply ----
if ($Apply) {
    if ($before.StartType -eq 'Manual' -and $before.State -eq 'Stopped') {
        'Nothing to do - already Manual and stopped.'; return
    }

    if (-not (Test-Path $BackupDir)) { $null = New-Item -ItemType Directory -Path $BackupDir -Force }
    $stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
    $statePath = Join-Path $BackupDir "hpdoctor-startup-$stamp.json"

    if ($PSCmdlet.ShouldProcess($statePath, 'Save prior state')) {
        $before | ConvertTo-Json -Depth 4 | Out-File -FilePath $statePath -Encoding utf8
        "Prior state saved: $statePath"
    }

    $changedStart = $false
    try {
        if ($PSCmdlet.ShouldProcess($SvcName, 'StartupType = Manual')) {
            Set-Service -Name $SvcName -StartupType Manual
            $changedStart = $true
            '  OK       start type -> Manual'
        }
        if ($PSCmdlet.ShouldProcess($SvcName, 'Stop service')) {
            Stop-Service -Name $SvcName -Force
            '  OK       service stopped'
        }
    }
    catch {
        '  FAILED   rolling back this run'
        if ($changedStart) { Restore-Default }
        throw "Could not apply: $($_.Exception.Message). Rolled back; nothing changed."
    }

    if ($WhatIfPreference) { return }

    # Failure actions are RESTART at 5s twice - soak past both before believing it.
    ''
    'Soaking 15s, past both 5s restart delays...'
    foreach ($i in 1..15) {
        Start-Sleep -Seconds 1
        $s = Get-HpState
        if ($s.State -ne 'Stopped' -or $s.StartValue -ne 3) {
            "  t+${i}s  came back (state=$($s.State), Start=$($s.StartValue)) - rolling back"
            Restore-Default
            throw "Did not stay stopped. Restored $DefaultStart."
        }
    }
    '  held for 15s.'

    Show-Status -S (Get-HpState)
    'Note: the two \HP\HP Print Scan Doctor\ scheduled tasks are NOT affected by this.'
    "Revert with:  .\Set-HpDoctorManual.ps1 -Revert"
    return
}

# ---------------------------------------------------------------- revert ----
if ($Revert) {
    $want = $DefaultStart
    $usedState = $false
    if (Test-Path $BackupDir) {
        $newest = Get-ChildItem -Path $BackupDir -Filter 'hpdoctor-startup-*.json' -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest) {
            try {
                $state = Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json
                if ($state.StartType -in 'Automatic','Manual') {
                    $want = $state.StartType; $usedState = $true
                    "Restoring the start type recorded in $($newest.Name): $want."
                }
            } catch { }
        }
    }
    if (-not $usedState) { "No usable saved state. Falling back to the known-good default: $DefaultStart + running." }

    if ($PSCmdlet.ShouldProcess($SvcName, "StartupType = $want")) {
        Set-Service -Name $SvcName -StartupType $want; "  OK       start type -> $want"
    }
    if ($PSCmdlet.ShouldProcess($SvcName, 'Start service')) {
        Start-Service -Name $SvcName -ErrorAction SilentlyContinue; '  OK       service started'
    }

    if ($WhatIfPreference) { return }
    ''
    Show-Status -S (Get-HpState)
    return
}
