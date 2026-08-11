<#
    Backup-SecureVault.ps1 - hourly copy of your vault folder to three
    destinations (edit $Source and the destination paths below to match your
    own setup):
        1. Documents\SecureVaultBackup       (if Documents is redirected to a
           cloud folder such as OneDrive, this becomes an OFFSITE encrypted copy)
        2. D:\SV\SecureVault                 (removable USB stick, exFAT)
        3. X:\SV\SecureVault                 (network share, skipped when away)

        (no switch)   read-only status
        -Apply        register the hourly Scheduled Task
        -Revert       remove the task (leaves existing backups in place)
        -RunNow       run one backup pass immediately (foreground)
        -ForceX       with -RunNow, run the X: leg even if it is not due yet
        -ForceD       with -RunNow, run the D: leg even if it is not due yet
        -RepinD       accept whatever volume is currently mounted as D: as the
                      backup stick (see VOLUME PINNING below)

    WHY X: RUNS EVERY 6 HOURS AND DOCUMENTS RUNS HOURLY
    X: is a NETWORK share (e.g. \\nas.example.lan\share), so its leg is 10 GB over SMB and
    takes long enough that hourly runs were overlapping the next trigger and
    being killed - LastTaskResult 3221225786 (0xC000013A, terminated), with
    START X-drive lines in the log that never got a matching OK.

    Rather than raise the execution time limit and let a doomed copy run longer,
    the X: leg is rate-limited to once every -XDriveIntervalHours (default 6).
    Documents stays hourly, because that is the copy that actually goes offsite;
    X: is the redundant one. D: is a local USB bus, not SMB, so it defaults to
    every pass (-DDriveIntervalHours 0); raise it if backup.log ever shows D:
    passes running long enough to collide with the next hour.

    The gate is a timestamp of the last SUCCESSFUL pass per leg, kept in the log
    directory. If that file is missing or unreadable the leg is treated as DUE -
    the failure mode is copying more often than intended, never silently
    skipping backups. A pass that skips a leg because the drive is detached does
    not update the timestamp, so the next hourly pass picks it up.

    Same house rules as the other scripts (see the revert-first pattern):
      - NON-destructive by design: robocopy runs WITHOUT /MIR or /PURGE, so a
        backup NEVER deletes files just because the source lost them. Backups
        only ever gain/refresh files.
      - Refuses to run if the source is missing SecureVault.dat, so a broken
        source can't propagate emptiness anywhere.
      - Each destination is independent: an unavailable X: (travelling) or an
        unplugged D: is logged and skipped, the other copies still run.
      - The task is laptop-aware: runs on battery and catches up if a scheduled
        hour was missed while the machine was asleep/off.

    NOTE on the 10 GB container: robocopy copies a file only when it has changed
    (size/timestamp), so idle hours are ~instant. When the .dat HAS changed the
    whole 10 GB is copied (there is no in-file delta copy on Windows), and for
    the Documents target that then becomes a ~10 GB OneDrive upload. That is the
    cost of an offsite copy of a single large container.

    WHY THE COPIES ARE CHAINED (source -> Documents -> D:/X:) AND NOT ALL FROM SOURCE
    Originally both destinations read from the source vault folder, which meant the live
    10.9 GB vault was read TWICE per pass - once quickly to local disk, and once
    slowly to X:. That second read holds the .dat open for as long as the slow
    link takes, and that is what was stalling edits to the vault. Adding a third
    destination that read from S: would make it three.

    So the passes are ordered and chained:

        stage 1   <vault folder>          -> Documents    local, fast, /J
        stage 2   Documents\SecureVault   -> D:\SV        USB,  /Z /FFT
                  Documents\SecureVault   -> X:\SV        SMB,  /Z
                                                          neither touches S:

    S: is read exactly once per pass, at local-disk speed, no matter how many
    stage-2 destinations there are. The long transfers read from the local
    Documents copy, so the vault is free the moment stage 1 finishes.

    THE TRADE, STATED: stage 2 mirrors the Documents copy rather than the vault
    directly, so a bad Documents copy could propagate. Guarded three ways -
    stage 2 only chains if stage 1 actually succeeded, if the Documents copy has
    the sentinel, and if its .dat matches the source in size AND timestamp. If
    any of those fail, stage 2 FALLS BACK to copying from S: directly and says
    so in the log. A detached OneDrive or a failed stage 1 must never silently
    stop the other copies from being taken.

    WHY THE D: LEG PASSES /FFT
    D: is exFAT, which stores timestamps at 10 ms granularity; NTFS stores them
    at 100 ns. A faithful copy therefore comes back with a LastWriteTime up to
    10 ms off the source, and robocopy's default compare is exact - so without
    /FFT (assume FAT times, 2-second precision) it would decide the .dat had
    changed and re-copy all 10 GB on EVERY hourly pass.

    VOLUME PINNING ON D:
    Removable drive letters get reused: unplug this stick, plug in a different
    one, and Windows may well hand it D: as well. Writing a 10 GB vault onto
    whatever happens to be mounted is not a backup. So the volume's identity is
    recorded on first use (d-drive-volume.txt) and checked on every pass after.
    A positive mismatch fails CLOSED - that is a definite "different device".
    An identity that cannot be READ at all fails open with a warning, keeping
    the rule that uncertainty means copy, never silently skip. Swapping in a new
    backup stick on purpose is one run with -RepinD.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch] $Apply,
    [switch] $Revert,
    [switch] $RunNow,
    [switch] $ForceX,
    [switch] $ForceD,
    [switch] $RepinD,
    [ValidateRange(0, 168)] [int] $XDriveIntervalHours = 6,  # 0 = every pass
    [ValidateRange(0, 168)] [int] $DDriveIntervalHours = 0   # local USB, so hourly
)

$ErrorActionPreference = 'Stop'

$Source   = "$env:LOCALAPPDATA\SecureVault"   # your vault folder - edit to match your install
$TaskName = 'SecureVault-HourlyBackup'
$ThisScript = $MyInvocation.MyCommand.Path
$LogDir   = Join-Path $env:LOCALAPPDATA 'SecureVault\backup-logs'
$Sentinel = 'SecureVault.dat'          # source must contain this or we abort

function Get-Destinations {
    <#  Stage 1 is the copy taken from the live vault; stage 2 destinations
        chain off stage 1's result and never read S:. Everything downstream -
        the backup loop, the status display, the -Apply summary - is driven off
        this one list, so a new destination is added here and nowhere else.

        DriveLetter is set only for removable media that needs volume pinning.
        FatTimes adds /FFT for filesystems with coarse timestamps (exFAT/FAT).  #>
    $docs = [Environment]::GetFolderPath('MyDocuments')
    @(
        [pscustomobject]@{ Name = 'Documents'; Path = (Join-Path $docs 'SecureVaultBackup')
                           RootProbe = $docs; Stage = 1
                           IntervalHours = 0; Force = $false; ForceFlag = ''
                           DriveLetter = $null; FatTimes = $false }
        [pscustomobject]@{ Name = 'D-drive';   Path = 'D:\SV\SecureVault'
                           RootProbe = 'D:\';  Stage = 2
                           IntervalHours = $DDriveIntervalHours
                           Force = [bool]$ForceD; ForceFlag = '-ForceD'
                           DriveLetter = 'D'; FatTimes = $true }
        [pscustomobject]@{ Name = 'X-drive';   Path = 'X:\SV\SecureVault'
                           RootProbe = 'X:\';  Stage = 2
                           IntervalHours = $XDriveIntervalHours
                           Force = [bool]$ForceX; ForceFlag = '-ForceX'
                           DriveLetter = $null; FatTimes = $false }
    )
}

function Write-Log {
    param($Message)
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path (Join-Path $LogDir 'backup.log') -Value $line -Encoding utf8
    Write-Host $line
}

# ------------------------------------------------------------------ one pass
function Copy-Tree {
    <#  One robocopy pass. Returns $true on success.
        $Mode 'local' uses /J (unbuffered I/O), which is markedly faster for a
        single 10 GB file on local disk and is the whole point of doing the S:
        read first. $Mode 'link' uses /Z (restartable) instead, because a
        transfer to a detachable or networked destination is the one that gets
        interrupted. /J and /Z fight each other, so never pass both.
        -FatTimes adds /FFT for exFAT/FAT destinations - see the header.  #>
    param(
        [Parameter(Mandatory)] [string] $From,
        [Parameter(Mandatory)] [string] $To,
        [Parameter(Mandatory)] [string] $Name,
        [ValidateSet('local','link')] [string] $Mode = 'link',
        [switch] $FatTimes
    )
    if (-not (Test-Path $To)) {
        try { New-Item -ItemType Directory -Path $To -Force | Out-Null }
        # ${Name} braces are required: "$Name:" would parse as a drive-qualified
        # variable reference and fail at parse time, not at run time.
        catch { Write-Log "SKIP ${Name}: cannot create $To - $($_.Exception.Message)"; return $false }
    }
    $rlog = Join-Path $LogDir "robocopy-$Name.log"
    $tuning = if ($Mode -eq 'local') { '/J' } else { '/Z' }
    # /E all subdirs, retries small so a locked file doesn't stall the hour.
    # NO /MIR and NO /PURGE - a backup never deletes what the source lost.
    $roboArgs = @($From, $To, '/E', $tuning, '/R:2', '/W:5', '/NP', '/NDL', '/NFL',
                  '/XA:SH', "/LOG+:$rlog", '/TEE')
    if ($FatTimes) { $roboArgs += '/FFT' }
    Write-Log "START ${Name} : $From -> $To  ($Mode)"
    & robocopy @roboArgs | Out-Null
    $rc = $LASTEXITCODE
    # robocopy: 0-7 = success (bits: 1 copied, 2 extra, 4 mismatch); >=8 = error
    if ($rc -ge 8) { Write-Log "ERROR ${Name} : robocopy exit $rc (see $rlog)"; return $false }
    Write-Log "OK    ${Name} : robocopy exit $rc"
    return $true
}

# ------------------------------------------------- stage-2 leg rate limiting
function Get-StatePath { param([Parameter(Mandatory)][string] $Name)
                         Join-Path $LogDir "$($Name.ToLower())-last.txt" }

function Read-StateTime {
    <#  Returns the recorded timestamp, or $null if there isn't a usable one.
        Every unusable case - absent, empty, corrupt, dated in the future -
        collapses to $null, and every caller reads $null as "due now".  #>
    param([Parameter(Mandatory)][string] $Name)
    $path = Get-StatePath $Name
    if (-not (Test-Path $path)) { return $null }
    try   { $last = [datetime]::Parse((Get-Content -LiteralPath $path -Raw).Trim(), $null,
                                      [Globalization.DateTimeStyles]::RoundtripKind) }
    catch { return $null }
    # A timestamp in the future means the clock moved or the file is junk.
    if ($last -gt (Get-Date).AddMinutes(5)) { return $null }
    return $last
}

function Test-Due {
    <#  Due unless a readable timestamp says the last SUCCESSFUL pass for this
        leg was within its interval. Missing/corrupt state must mean "copy it",
        never "skip it".  #>
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][int] $IntervalHours)
    if ($IntervalHours -le 0) { return $true }
    $last = Read-StateTime $Name
    if ($null -eq $last) { return $true }
    return ((Get-Date) - $last).TotalHours -ge $IntervalHours
}

function Set-Done {
    param([Parameter(Mandatory)][string] $Name)
    try { (Get-Date).ToString('o') | Set-Content -LiteralPath (Get-StatePath $Name) -Encoding utf8 }
    catch { Write-Log "WARN: could not record the $Name timestamp - $($_.Exception.Message)" }
}

function Get-NextDue {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][int] $IntervalHours)
    if ($IntervalHours -le 0) { return 'every pass' }
    if (-not (Test-Path (Get-StatePath $Name))) { return 'due now (never recorded)' }
    $last = Read-StateTime $Name
    if ($null -eq $last) { return 'due now (unreadable state file)' }
    $next = $last.AddHours($IntervalHours)
    if ($next -le (Get-Date)) { return "due now (last ran $last)" }
    return "$next  (last ran $last)"
}

# ------------------------------------------------- removable volume identity
function Get-PinPath { param([Parameter(Mandatory)][string] $Name)
                       Join-Path $LogDir "$($Name.ToLower())-volume.txt" }

function Get-VolumeId {
    param([Parameter(Mandatory)][string] $DriveLetter)
    try { return (Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop).UniqueId } catch { return $null }
}

function Test-VolumePinned {
    <#  See VOLUME PINNING in the header. Fail CLOSED on a positive mismatch,
        fail OPEN when the identity cannot be read at all.  #>
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $DriveLetter)

    $pin = Get-PinPath $Name
    $id  = Get-VolumeId $DriveLetter
    if ([string]::IsNullOrWhiteSpace($id)) {
        Write-Log "WARN  ${Name}: cannot read the volume id for ${DriveLetter}: - proceeding unverified."
        return $true
    }
    if ($RepinD) {
        if (Set-Pin -Name $Name -Id $id) { Write-Log "REPIN ${Name}: now pinned to volume $id" }
        return $true
    }
    if (-not (Test-Path $pin)) {
        if (Set-Pin -Name $Name -Id $id) { Write-Log "PIN   ${Name}: first use, pinned to volume $id" }
        return $true
    }
    $want = ''
    try { $want = (Get-Content -LiteralPath $pin -Raw).Trim() } catch { }
    # An unreadable pin file is no evidence of a wrong device, so fail open and
    # rewrite it rather than blocking every future backup on a corrupt file.
    if ([string]::IsNullOrWhiteSpace($want)) {
        if (Set-Pin -Name $Name -Id $id) { Write-Log "PIN   ${Name}: pin file was unreadable, re-pinned to $id" }
        return $true
    }
    if ($want -eq $id) { return $true }
    Write-Log ("SKIP  {0}: {1}: is volume {2}, not the pinned backup volume {3}. " -f $Name, $DriveLetter, $id, $want +
               "Re-run with -RepinD to accept this device.")
    return $false
}

function Set-Pin {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Id)
    try { $Id | Set-Content -LiteralPath (Get-PinPath $Name) -Encoding utf8; return $true }
    catch { Write-Log "WARN  ${Name}: could not record the volume pin - $($_.Exception.Message)"; return $false }
}

function Invoke-Backup {
    $srcDat = Join-Path $Source $Sentinel
    if (-not (Test-Path $srcDat)) {
        Write-Log "ABORT: source $Source has no $Sentinel - refusing to back up an empty/broken source."
        return 1
    }
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

    $dests = Get-Destinations
    $docs = $dests | Where-Object Stage -eq 1
    $overall = 0
    $stage1Ok = $false

    # ---- stage 1: S: -> Documents. Local disk, so the vault is released fast.
    if (Test-Path $docs.RootProbe) {
        $stage1Ok = Copy-Tree -From $Source -To $docs.Path -Name $docs.Name -Mode local
        if (-not $stage1Ok) { $overall = 1 }
    } else {
        Write-Log "SKIP $($docs.Name): $($docs.RootProbe) not available (not signed in)."
    }

    # Chain only from a copy we have just proved current. BOTH checks are
    # needed. Size alone is not enough: this container is append-only, so an
    # edit that rewrites in place leaves the size identical while the contents
    # differ, and the stage-2 copies would silently inherit a stale vault.
    # robocopy preserves timestamps, so a good copy has the same LastWriteTime
    # as the source - compared with a 2-second tolerance for fs granularity.
    # Computed once: it is the same answer for every stage-2 destination.
    $docsDat = Join-Path $docs.Path $Sentinel
    $chainFrom = $Source
    $why = 'stage 1 did not produce a usable copy'
    if ($stage1Ok -and (Test-Path $docsDat)) {
        $src = Get-Item $srcDat
        $cpy = Get-Item $docsDat
        $skew = [math]::Abs(($cpy.LastWriteTime - $src.LastWriteTime).TotalSeconds)
        if ($cpy.Length -ne $src.Length) {
            $why = "the Documents .dat is $($cpy.Length) bytes, source is $($src.Length)"
        } elseif ($skew -gt 2) {
            $why = ("the Documents .dat is dated {0} but the source is {1}" -f
                    $cpy.LastWriteTime, $src.LastWriteTime)
        } else {
            $chainFrom = $docs.Path
            $why = $null
        }
    }

    # ---- stage 2: Documents -> D: and X:, so no slow link ever reads the live
    # vault. Each leg is independent: one being unplugged, not yet due or
    # pointing at the wrong volume must not stop the others.
    foreach ($lnk in ($dests | Where-Object Stage -eq 2)) {
        if (-not $lnk.Force -and -not (Test-Due -Name $lnk.Name -IntervalHours $lnk.IntervalHours)) {
            Write-Log ("SKIP  {0}: every {1} h, next due {2}. {3} overrides." -f $lnk.Name,
                       $lnk.IntervalHours, (Get-NextDue -Name $lnk.Name -IntervalHours $lnk.IntervalHours),
                       $lnk.ForceFlag)
            continue
        }
        if (-not (Test-Path $lnk.RootProbe)) {
            # Deliberately does NOT record a timestamp, so the next hourly pass
            # retries rather than waiting out the full interval.
            Write-Log "SKIP  $($lnk.Name): $($lnk.RootProbe) not available (detached / travelling)."
            continue
        }
        # Removable media only: never write the vault to an unrecognised device.
        if ($lnk.DriveLetter -and -not (Test-VolumePinned -Name $lnk.Name -DriveLetter $lnk.DriveLetter)) {
            continue
        }
        if ($why) {
            Write-Log "FALLBACK $($lnk.Name): copying direct from $Source because $why."
        }
        if (Copy-Tree -From $chainFrom -To $lnk.Path -Name $lnk.Name -Mode link -FatTimes:$lnk.FatTimes) {
            # Only a SUCCESSFUL pass restarts the clock. A failed or killed copy
            # leaves the leg due, so the next hourly pass retries it.
            Set-Done -Name $lnk.Name
        } else {
            $overall = 1
        }
    }
    return $overall
}

# --------------------------------------------------------------------- task
function Invoke-Apply {
    if (-not $PSCmdlet.ShouldProcess($TaskName, 'register hourly SecureVault backup task')) { return }
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
                 -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ThisScript`" -RunNow"
    # start on the next hour boundary, then every hour, forever
    $start   = (Get-Date).Date.AddHours((Get-Date).Hour + 1)
    # Omit RepetitionDuration entirely -> repeat indefinitely. Passing
    # [TimeSpan]::MaxValue serialises to an out-of-range XML duration and fails.
    $trigger = New-ScheduledTaskTrigger -Once -At $start `
                 -RepetitionInterval (New-TimeSpan -Hours 1)
    $princ   = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
    # laptop-aware: run on battery, don't die on battery, catch up if missed
    $set     = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                 -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $princ -Settings $set -Force | Out-Null
    Write-Host "  registered '$TaskName' - hourly from $start" -ForegroundColor Green
    Write-Host "  destinations:" -ForegroundColor Green
    Get-Destinations | ForEach-Object { Write-Host "     $($_.Name): $($_.Path)" }
    Write-Host "  Documents resolves to OneDrive - that copy syncs offsite to the cloud." -ForegroundColor Yellow
    Write-Host "  Run one now with:  .\Backup-SecureVault.ps1 -RunNow" -ForegroundColor DarkGray
}

function Invoke-Revert {
    if (-not $PSCmdlet.ShouldProcess($TaskName, 'remove the hourly backup task')) { return }
    if (Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "  removed '$TaskName'. Existing backups were left in place." -ForegroundColor Green
    } else { Write-Host "  no task '$TaskName' registered." -ForegroundColor DarkGray }
}

# ------------------------------------------------------------------- status
function Show-Status {
    Write-Host "==== SECUREVAULT HOURLY BACKUP ====" -ForegroundColor Cyan
    $srcDat = Join-Path $Source $Sentinel
    if (Test-Path $srcDat) {
        $s = Get-Item $srcDat
        "  source .dat : {0:N2} GB, modified {1}" -f ($s.Length/1GB), $s.LastWriteTime
    } else { Write-Host "  source $Sentinel MISSING - backup would abort." -ForegroundColor Red }

    $t = Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
    if ($t) {
        $info = Get-ScheduledTaskInfo $t
        "  task        : registered ($($t.State))"
        "  last run    : $($info.LastRunTime)  (result $($info.LastTaskResult))"
        "  next run    : $($info.NextRunTime)"
    } else { Write-Host "  task        : NOT registered - run -Apply" -ForegroundColor Yellow }

    $dests = Get-Destinations
    Write-Host "`n  copy order (chained so S: is read once per pass):"
    Write-Host "     1. <vault folder>        -> Documents   hourly, local, /J" -ForegroundColor DarkGray
    $n = 1
    foreach ($lnk in ($dests | Where-Object Stage -eq 2)) {
        $n++
        $every = if ($lnk.IntervalHours -le 0) { 'every pass' } else { "every $($lnk.IntervalHours) h" }
        $flags = '/Z' + $(if ($lnk.FatTimes) { ' /FFT' } else { '' })
        Write-Host ("     {0}. Documents             -> {1,-11} {2}, {3}, never reads S:" -f
                    $n, $lnk.Path.Substring(0,5), $every, $flags) -ForegroundColor DarkGray
        Write-Host ("        {0} next due: {1}" -f $lnk.Name,
                    (Get-NextDue -Name $lnk.Name -IntervalHours $lnk.IntervalHours)) -ForegroundColor DarkGray
    }
    Write-Host "        (stage 2 falls back to copying direct from S: if stage 1" -ForegroundColor DarkGray
    Write-Host "         failed or its .dat does not match the source)" -ForegroundColor DarkGray

    Write-Host "`n  destinations:"
    foreach ($d in $dests) {
        $avail = Test-Path $d.RootProbe
        $destDat = Join-Path $d.Path $Sentinel
        $freshness = if (Test-Path $destDat) {
            $b = Get-Item $destDat
            "copy {0:N2} GB, {1}" -f ($b.Length/1GB), $b.LastWriteTime
        } elseif ($avail) { "no copy yet" } else { "" }
        $mark = if ($avail) { 'available ' } else { 'OFFLINE   ' }
        Write-Host ("     {0,-10} {1} {2}" -f $d.Name, $mark, $freshness) `
            -ForegroundColor $(if ($avail) { 'Gray' } else { 'Yellow' })
        if ($d.Name -eq 'Documents' -and $d.Path -match 'OneDrive') {
            Write-Host "                (OneDrive - this copy uploads offsite to the cloud)" -ForegroundColor DarkGray
        }
        if ($d.DriveLetter) {
            # Removable: say out loud whether the stick currently on that letter
            # is the pinned one, because a silent SKIP is easy to miss.
            $pin = Get-PinPath $d.Name
            if (-not (Test-Path $pin)) {
                Write-Host "                (removable - not pinned yet, first backup pins it)" -ForegroundColor DarkGray
            } elseif ($avail) {
                $want = (Get-Content -LiteralPath $pin -Raw).Trim()
                $id   = Get-VolumeId $d.DriveLetter
                if ($id -and $id -ne $want) {
                    Write-Host "                (WRONG VOLUME on $($d.DriveLetter): - backups skipped. -RepinD to accept it)" -ForegroundColor Red
                } else {
                    Write-Host "                (removable - pinned volume verified)" -ForegroundColor DarkGray
                }
            }
        }
    }
    $log = Join-Path $LogDir 'backup.log'
    if (Test-Path $log) {
        Write-Host "`n  last log lines:" -ForegroundColor Cyan
        Get-Content $log -Tail 6 | ForEach-Object { "     $_" }
    }
}

# ---------------------------------------------------------------------- main
if ($Apply -and $Revert) { throw "Pick one of -Apply or -Revert." }
if     ($RunNow) { exit (Invoke-Backup) }
elseif ($Revert) { Invoke-Revert }
elseif ($Apply)  { Invoke-Apply }
else             { Show-Status }
