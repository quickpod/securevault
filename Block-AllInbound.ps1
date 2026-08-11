<#
    Block-AllInbound.ps1  -  stop ALL inbound connections, including allowed apps

    RUN IN AN ELEVATED (Administrator) PowerShell.

    WHAT THIS ACTUALLY CHANGES
    DefaultInboundAction is ALREADY Block on all three profiles. That is not the
    gap. The gap is that default-deny only decides traffic no RULE matched, and
    this machine has 89 enabled inbound allow rules - 56 of them live on the
    Public profile, 41 scoped to any remote address. Those rules are the
    exceptions that punch through default-deny.

    The switch that makes them stop applying is AllowInboundRules=False. It is
    the same thing as the "Block all incoming connections, including those in
    the list of allowed apps" checkbox in the Windows Firewall control panel.
    After this, an inbound packet is dropped even if a rule says allow.

    WHAT KEEPS WORKING (this is the important part)
    The firewall is STATEFUL. Anything your machine starts is unaffected:
    browsing, email, DNS/DoH, Windows Update, OneDrive, VPN clients, and Teams
    or Zoom CALLS - the media flows back on a connection you opened. This does
    not "cut you off the internet"; it only stops connections that OTHERS start
    to you.

    WHAT STOPS WORKING
      - Casting / Miracast / wireless display, Wi-Fi Direct, Nearby Sharing
      - Phone Link and similar device pairing over the LAN
      - Anything remoting INTO this box (RDP, SMB shares) - already off here
      - Discovery of new network printers. Printing to an already-installed
        printer still works: that is an outbound connection.
      - Peer-to-peer Windows Update delivery (Delivery Optimization)

      (no switches)   Read-only status.
      -Apply          Block all inbound, verify connectivity, auto-roll back on
                      failure.
      -Revert         Restore the saved previous settings (or Windows defaults).
      -Profiles       Which profiles to change. Default: all three. Use
                      -Profiles Public to harden only untrusted networks and
                      leave home/office behaviour alone.
      -AlsoDisableCastRules
                      Additionally DISABLE the Wireless Display / WFD /
                      Proximity inbound rules. Defence in depth: if
                      AllowInboundRules is ever turned back on, tcp/7250 does
                      not silently reopen to the whole subnet with it.
      -ArmDeadMan N   One-shot task that runs -Revert in N minutes unless you
                      -Disarm. Survives a reboot.
      -Disarm         Cancel the dead-man task.

    Supports -WhatIf on every mutation.

    THIS IS ONE COMMAND TO UNDO. If something you need breaks:
        .\Block-AllInbound.ps1 -Revert
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Apply')]  [switch]$Apply,
  [Parameter(ParameterSetName = 'Apply')]  [switch]$AlsoDisableCastRules,
  [Parameter(ParameterSetName = 'Revert')] [switch]$Revert,
  [Parameter(ParameterSetName = 'Disarm')] [switch]$Disarm,
  [ValidateSet('Domain', 'Private', 'Public')]
  [string[]]$Profiles = @('Domain', 'Private', 'Public'),
  [int]$ArmDeadMan = 0
)

$ErrorActionPreference = 'Continue'

$StateDir  = 'C:\SecureVault\Backups'
$StateFile = Join-Path $StateDir 'firewall-inbound-lastgood.json'
$TaskName  = 'SecureVault-Firewall-DeadMan'
$CastRules = @('Wireless Display*', 'WFD *', 'Proximity sharing*', 'Cast to Device*')

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

# ---------------------------------------------------------------- helpers ----

function Get-InboundStatus {
  $rows = foreach ($p in Get-NetFirewallProfile) {
    # AllowInboundRules is what decides whether the 89 allow rules mean
    # anything. DefaultInboundAction alone is not the whole picture, which is
    # why a machine can look "default deny" and still have 56 open exceptions.
    [pscustomobject]@{
      Profile           = $p.Name
      Enabled           = $p.Enabled
      DefaultInbound    = $p.DefaultInboundAction
      AllowInboundRules = $p.AllowInboundRules
      FullyBlocked      = ($p.Enabled -eq 'True' -and
                           $p.DefaultInboundAction -eq 'Block' -and
                           $p.AllowInboundRules -eq 'False')
    }
  }
  $rows
}

function Get-LiveProfileName {
  # Which profile is actually governing the connected adapter right now. A
  # change to Public is meaningless if this laptop is sitting on a Private
  # network, and vice versa - so always report it.
  $c = Get-NetConnectionProfile -EA SilentlyContinue | Select-Object -First 1
  if ($c) { "$($c.NetworkCategory)" } else { 'unknown' }
}

function Test-Connectivity {
  # Three independent signals. Inbound blocking should not affect ANY of them,
  # because all three are outbound-initiated. If one fails we over-blocked
  # something and should back out rather than leave the user stranded.
  $r = [ordered]@{}

  $r.HasIP = [bool](Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue |
                    Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' })

  $ok = 0
  foreach ($n in 'microsoft.com', 'cloudflare.com', 'example.com') {
    if (Resolve-DnsName $n -Type A -EA SilentlyContinue -QuickTimeout) { $ok++ }
  }
  $r.DnsPassed = $ok
  $r.Dns = ($ok -ge 2)

  $r.Tcp443 = [bool](Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)

  $r.Healthy = ($r.HasIP -and $r.Dns -and $r.Tcp443)
  [pscustomobject]$r
}

function Save-State {
  if (-not (Test-Path $StateDir)) { New-Item $StateDir -ItemType Directory -Force | Out-Null }
  $snap = foreach ($p in Get-NetFirewallProfile) {
    [pscustomobject]@{
      Name                  = $p.Name
      Enabled               = "$($p.Enabled)"
      DefaultInboundAction  = "$($p.DefaultInboundAction)"
      AllowInboundRules     = "$($p.AllowInboundRules)"
      NotifyOnListen        = "$($p.NotifyOnListen)"
    }
  }
  # Record which cast-family rules were ENABLED before we touched them, so the
  # revert re-enables exactly those and does not switch on rules that were
  # already off for some other reason.
  # NOTE: -DisplayName and -Direction cannot be combined - Get-NetFirewallRule
  # puts them in different parameter sets and throws "Parameter set cannot be
  # resolved". With -EA SilentlyContinue that failure is INVISIBLE: it returns
  # nothing and looks exactly like "no rules matched". Filter direction after
  # the fact instead.
  $enabledCast = @(Get-NetFirewallRule -DisplayName $CastRules -EA SilentlyContinue |
                     Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' } |
                     ForEach-Object { $_.Name })

  [pscustomobject]@{
    SavedAt      = (Get-Date).ToString('s')
    Profiles     = $snap
    EnabledCast  = @($enabledCast)
  } | ConvertTo-Json -Depth 5 | Out-File $StateFile -Encoding utf8
  Write-Host "  Saved previous firewall state to $StateFile" -ForegroundColor DarkGray
}

function Restore-Defaults {
  # Used when no state file exists. Windows stock: profile on, inbound blocked
  # by default, allow rules honoured.
  foreach ($p in @('Domain', 'Private', 'Public')) {
    Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block -AllowInboundRules True -EA SilentlyContinue
  }
  Write-Host "  All profiles reset to Windows defaults (inbound rules honoured again)" -ForegroundColor Green
}

function Remove-DeadMan {
  if (Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "  Dead-man task '$TaskName' removed" -ForegroundColor Green
    return $true
  }
  $false
}

# ------------------------------------------------------------------ disarm ---

if ($Disarm) {
  Write-Host "`n==== DISARM ====" -ForegroundColor Cyan
  if (-not (Remove-DeadMan)) { Write-Host "  No dead-man task was armed." -ForegroundColor Yellow }
  return
}

# ------------------------------------------------------------------ status ---

Write-Host "`n==== INBOUND FIREWALL STATUS ====" -ForegroundColor Cyan
Get-InboundStatus | Format-Table -AutoSize
Write-Host "  Live profile on the connected adapter: $(Get-LiveProfileName)" -ForegroundColor Cyan

$openRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -EA SilentlyContinue)
Write-Host "  Enabled inbound allow rules on the box: $($openRules.Count)" -ForegroundColor Cyan

if (Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue) {
  Write-Host "  NOTE: a dead-man revert is armed. Run -Disarm once you are happy." -ForegroundColor Yellow
}

if ($PSCmdlet.ParameterSetName -eq 'Status') {
  $live = Get-LiveProfileName
  $lp   = Get-InboundStatus | Where-Object Profile -eq $live
  Write-Host "Read-only check. Nothing changed." -ForegroundColor Yellow
  if ($lp -and $lp.FullyBlocked) {
    Write-Host "`nALL inbound is blocked on the live profile ($live), allow rules included." -ForegroundColor Green
  } else {
    Write-Host "`nInbound allow rules are still honoured - $($openRules.Count) exceptions can pass." -ForegroundColor Yellow
    Write-Host "    .\Block-AllInbound.ps1 -Apply" -ForegroundColor Yellow
  }
  return
}

# ------------------------------------------------------------------ revert ---

if ($Revert) {
  Write-Host "`n==== REVERT ====" -ForegroundColor Cyan

  if (Test-Path $StateFile) {
    $st = Get-Content $StateFile -Raw | ConvertFrom-Json
    Write-Host "  Restoring state saved $($st.SavedAt)" -ForegroundColor Yellow
    foreach ($p in $st.Profiles) {
      if ($PSCmdlet.ShouldProcess("$($p.Name) profile", "Restore AllowInboundRules=$($p.AllowInboundRules)")) {
        Set-NetFirewallProfile -Profile $p.Name `
          -Enabled $p.Enabled `
          -DefaultInboundAction $p.DefaultInboundAction `
          -AllowInboundRules $p.AllowInboundRules -EA SilentlyContinue
        "  $($p.Name): inbound=$($p.DefaultInboundAction), allow rules honoured=$($p.AllowInboundRules)"
      }
    }
    # Guard against nulls: an older state file written while the cast query was
    # broken contains [null], and a bare .Count of 1 would pass a naive check.
    $cast = @($st.EnabledCast | Where-Object { $_ })
    if ($cast.Count) {
      if ($PSCmdlet.ShouldProcess('cast/WFD/proximity rules', "Re-enable $($cast.Count) rule(s)")) {
        foreach ($n in $cast) { Enable-NetFirewallRule -Name $n -EA SilentlyContinue }
        "  Re-enabled $($cast.Count) cast/WFD/proximity rule(s) that were on before"
      }
    }
  } else {
    Write-Host "  No saved state - falling back to Windows defaults." -ForegroundColor Yellow
    if ($PSCmdlet.ShouldProcess('all profiles', 'Reset to Windows defaults')) { Restore-Defaults }
  }

  Remove-DeadMan | Out-Null

  Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
  Get-InboundStatus | Format-Table -AutoSize
  $t = Test-Connectivity
  if ($t.Healthy) { Write-Host "Connectivity OK (IP yes, DNS $($t.DnsPassed)/3, tcp/443 yes)." -ForegroundColor Green }
  else {
    Write-Host @"
Connectivity still degraded after revert (IP=$($t.HasIP) DNS=$($t.DnsPassed)/3 tcp443=$($t.Tcp443)).
The firewall has already been handed back, so inbound blocking is NOT the cause.
Check the DNS layer next:
    .\Set-EncryptedDns.ps1 -Revert
    .\Revert-FixGaps.ps1 -RepairDns
"@ -ForegroundColor Red
  }
  return
}

# ------------------------------------------------------------------- apply ---

Write-Host "`n==== APPLY: block ALL inbound on $($Profiles -join ', ') ====" -ForegroundColor Cyan

$live = Get-LiveProfileName
if ($live -ne 'unknown' -and $Profiles -notcontains $live) {
  Write-Host "  WARNING: the connected network is '$live', which is NOT in -Profiles." -ForegroundColor Red
  Write-Host "  This change will have no effect on the network you are on right now." -ForegroundColor Red
}

if ($ArmDeadMan -gt 0) {
  if ($PSCmdlet.ShouldProcess("scheduled task $TaskName", "Arm auto-revert in $ArmDeadMan minutes")) {
    Remove-DeadMan | Out-Null
    # Same reasoning as Set-EncryptedDns: run from the OS drive, because the
    # task may fire after a reboot and S: is not guaranteed mounted/unlocked.
    $taskCopy = 'C:\SecureVault\Block-AllInbound.ps1'
    try {
      if (-not (Test-Path 'C:\SecureVault')) { New-Item 'C:\SecureVault' -ItemType Directory -Force | Out-Null }
      Copy-Item $PSCommandPath $taskCopy -Force -EA Stop
      Write-Host "  Dead-man will run from $taskCopy" -ForegroundColor DarkGray
    } catch {
      Write-Warning "  Could not stage a copy on C: ($($_.Exception.Message)) - using $PSCommandPath"
      $taskCopy = $PSCommandPath
    }
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$taskCopy`" -Revert"
    $trg = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($ArmDeadMan))
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Principal $pr `
                           -Description 'Auto-revert inbound firewall block if not disarmed' | Out-Null
    Write-Host "  DEAD MAN ARMED: reverts at $((Get-Date).AddMinutes($ArmDeadMan).ToString('HH:mm:ss')) unless you run -Disarm" -ForegroundColor Yellow
  }
}

Save-State

foreach ($p in $Profiles) {
  if ($PSCmdlet.ShouldProcess("$p profile", 'Block all inbound including allowed apps')) {
    try {
      Set-NetFirewallProfile -Profile $p -Enabled True `
                             -DefaultInboundAction Block `
                             -AllowInboundRules False -EA Stop
      Write-Host "  $p : ALL inbound blocked (allow rules no longer apply)" -ForegroundColor Green
    } catch {
      Write-Warning "  $p failed: $($_.Exception.Message)"
    }
  }
}

if ($AlsoDisableCastRules) {
  if ($PSCmdlet.ShouldProcess('cast/WFD/proximity inbound rules', 'Disable')) {
    # See Save-State: -DisplayName + -Direction is an unresolvable parameter set.
    $hit = @(Get-NetFirewallRule -DisplayName $CastRules -EA SilentlyContinue |
               Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' })
    if ($hit) {
      $hit | Disable-NetFirewallRule
      Write-Host "  Disabled $($hit.Count) cast/WFD/proximity inbound rule(s), incl. tcp/7250" -ForegroundColor Green
    } else { Write-Host "  No enabled cast/WFD/proximity rules to disable" -ForegroundColor DarkGray }
  }
}

# Give the stack a moment to settle before judging it.
Start-Sleep -Seconds 3
$t = Test-Connectivity

if (-not $t.Healthy) {
  Write-Host "`n  VERIFY FAILED (IP=$($t.HasIP) DNS=$($t.DnsPassed)/3 tcp443=$($t.Tcp443)) - rolling back." -ForegroundColor Red
  if (Test-Path $StateFile) {
    $st = Get-Content $StateFile -Raw | ConvertFrom-Json
    foreach ($p in $st.Profiles) {
      Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Enabled `
        -DefaultInboundAction $p.DefaultInboundAction `
        -AllowInboundRules $p.AllowInboundRules -EA SilentlyContinue
    }
    if ($st.EnabledCast) { foreach ($n in $st.EnabledCast) { Enable-NetFirewallRule -Name $n -EA SilentlyContinue } }
  } else { Restore-Defaults }
  Start-Sleep -Seconds 2
  $t2 = Test-Connectivity
  if ($t2.Healthy) {
    Write-Host "  Rolled back, connectivity restored." -ForegroundColor Green
    Write-Host "  Something on this network genuinely needs inbound. Try -Profiles Public only." -ForegroundColor Yellow
  } else {
    Write-Host "  Rollback did not restore connectivity - the fault is not the firewall." -ForegroundColor Red
    Write-Host "  Try: .\Set-EncryptedDns.ps1 -Revert   then   .\Revert-FixGaps.ps1 -RepairDns" -ForegroundColor Red
  }
  Remove-DeadMan | Out-Null
  return
}

Write-Host "  Connectivity verified (IP yes, DNS $($t.DnsPassed)/3, tcp/443 yes)" -ForegroundColor Green

Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
Get-InboundStatus | Format-Table -AutoSize

Write-Host @"
ALL inbound connections are now blocked on: $($Profiles -join ', ')
Outbound and anything you initiate is unaffected.

Undo:                .\Block-AllInbound.ps1 -Revert
Harden travel only:  .\Block-AllInbound.ps1 -Revert ; .\Block-AllInbound.ps1 -Apply -Profiles Public
"@ -ForegroundColor Cyan
