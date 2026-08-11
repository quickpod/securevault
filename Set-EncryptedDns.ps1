<#
    Set-EncryptedDns.ps1  -  point an adapter at DoH-capable resolvers, safely

    RUN IN AN ELEVATED (Administrator) PowerShell.

    WHY THIS IS SEPARATE FROM Fix-Gaps.ps1
    Fix-Gaps Section D only filled in Windows' DoH TEMPLATE TABLE - it told
    Windows "if you ever talk to 1.1.1.1, do it over HTTPS". It never changed
    which resolver the adapter uses. A typical adapter takes its DNS server from
    the local router over DHCP, so none of that table was ever consulted and
    nothing was encrypted. This script closes that gap, and ONLY that gap. It
    does not touch the Dnscache service key - overwriting that key with
    'New-Item -Force' wipes ServiceDll and breaks DNS on every adapter, so this
    script stays well clear of it.

    SAFETY MODEL
      - Every change is to per-adapter DNS server addresses. Nothing here can
        stop the DNS Client service, which is the only failure that leaves you
        with no way to resolve anything on any adapter.
      - Apply is self-verifying: it resolves several names afterwards and rolls
        itself back automatically if they fail. You should never be left with a
        broken resolver by a normal run.
      - The revert needs NO network, NO downloads and NO state file. Worst case
        it just hands the adapter back to DHCP, which is where it started.

      (no switches)   Read-only status. Tells you what is set and whether DoH
                      is actually carrying traffic right now.
      -Apply          Set the adapter to the DoH resolvers, verify, auto-roll
                      back on failure.
      -Revert         Undo. Hands DNS back to DHCP (or to the saved state).
      -Full           With -Revert, ALSO turn auto-upgrade back off in the
                      template table, returning Section D to stock.
      -ArmDeadMan N   Register a one-shot scheduled task that runs -Revert in N
                      minutes unless you -Disarm first. Survives a reboot. Use
                      this if you are about to test something you might not be
                      able to undo by hand.
      -Disarm         Cancel the dead-man task ("it works, stand down").

      -InterfaceAlias Defaults to the connected physical adapter.
      -Servers        Defaults to 1.1.1.1,8.8.8.8. Both MUST be entries that
                      have AutoUpgrade=True in the template table or their
                      queries go out in plaintext - 1.0.0.1 and 8.8.4.4 do NOT
                      by default, which is why they are not the secondaries.

    Supports -WhatIf on every mutation.

    IF A HOTEL / AIRPORT WI-FI WILL NOT LOAD ITS LOGIN PAGE: that is this
    change. Captive portals redirect you by intercepting DNS, and a portal that
    blocks port 53 to outside addresses will hang instead. Fix:
        .\Set-EncryptedDns.ps1 -Revert
    Re-apply once you are through the portal.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Apply')]  [switch]$Apply,
  [Parameter(ParameterSetName = 'Revert')] [switch]$Revert,
  [Parameter(ParameterSetName = 'Revert')] [switch]$Full,
  [Parameter(ParameterSetName = 'Disarm')] [switch]$Disarm,
  [string]$InterfaceAlias,
  [string[]]$Servers = @('1.1.1.1', '8.8.8.8'),
  [int]$ArmDeadMan = 0
)

$ErrorActionPreference = 'Continue'

$StateDir  = 'C:\SecureVault\Backups'
$StateFile = Join-Path $StateDir 'dns-adapter-lastgood.json'
$TaskName  = 'SecureVault-DNS-DeadMan'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

# ---------------------------------------------------------------- helpers ----

function Resolve-TargetAdapter {
  param([string]$Alias)
  if ($Alias) {
    $a = Get-NetAdapter -InterfaceAlias $Alias -EA SilentlyContinue
    if (-not $a) { throw "No adapter named '$Alias'. Adapters: $((Get-NetAdapter | ForEach-Object Name) -join ', ')" }
    return $a
  }
  # Auto-detect: an adapter that is Up, physical, and not a virtual/VPN shim.
  # Picking the fastest link breaks the tie if a dock is plugged in.
  # Sort on Speed (uint64), NOT LinkSpeed - LinkSpeed is a display string like
  # "459 Mbps" and sorts lexically, which would rank 9 Mbps above 459 Mbps.
  $cand = Get-NetAdapter -Physical -EA SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' } |
            Sort-Object -Property Speed -Descending
  if (-not $cand) { throw "No connected physical adapter found. Pass -InterfaceAlias explicitly." }
  $cand | Select-Object -First 1
}

function Get-DnsStatus {
  param([string]$Alias)

  $s = [ordered]@{}
  $s.Adapter = $Alias

  $v4 = Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv4 -EA SilentlyContinue
  $v6 = Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv6 -EA SilentlyContinue
  $s.IPv4Servers = if ($v4.ServerAddresses) { $v4.ServerAddresses -join ', ' } else { '<none>' }
  $s.IPv6Servers = if ($v6.ServerAddresses) { $v6.ServerAddresses -join ', ' } else { '<none>' }

  $ipif = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -EA SilentlyContinue
  $s.DhcpForIP = if ($ipif) { "$($ipif.Dhcp)" } else { 'unknown' }

  # Get-DnsClientServerAddress reports the servers in USE and cannot tell you
  # who chose them. The interface's NameServer registry value can: it holds the
  # statically configured list and is empty when DHCP is supplying them. That
  # is the difference between "we configured this" and "the router did".
  $guid = (Get-NetAdapter -InterfaceAlias $Alias -EA SilentlyContinue).InterfaceGuid
  $reg  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -EA SilentlyContinue
  $s.DnsIsStatic = -not [string]::IsNullOrWhiteSpace($reg.NameServer)

  # Which of the configured servers will actually be encrypted. A server with
  # AutoUpgrade=False is queried in cleartext even though DoH is "on".
  $tbl = Get-DnsClientDohServerAddress -EA SilentlyContinue
  $enc = @(); $plain = @()
  foreach ($srv in @($v4.ServerAddresses) + @($v6.ServerAddresses)) {
    if (-not $srv) { continue }
    $row = $tbl | Where-Object { $_.ServerAddress -eq $srv }
    if ($row -and $row.AutoUpgrade) { $enc += $srv } else { $plain += $srv }
  }
  $s.WillEncrypt   = if ($enc)   { $enc   -join ', ' } else { 'none' }
  $s.WillBePlain   = if ($plain) { $plain -join ', ' } else { 'none' }

  $s.EnableAutoDoh = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -EA SilentlyContinue).EnableAutoDoh
  if ($null -eq $s.EnableAutoDoh) { $s.EnableAutoDoh = '<not set>' }

  $s.Resolves = [bool](Resolve-DnsName microsoft.com -EA SilentlyContinue -QuickTimeout)

  # The only honest proof DoH is live: the DNS Client's host process holding an
  # established TCP/443 socket to one of the resolvers. Config says "should",
  # this says "is". Requires elevation to map the owning process.
  $live = @()
  try {
    $svcPids = (Get-CimInstance Win32_Service -Filter "Name='Dnscache'" -EA Stop).ProcessId
    $live = Get-NetTCPConnection -State Established -RemotePort 443 -OwningProcess $svcPids -EA SilentlyContinue |
              Where-Object { $_.RemoteAddress -in $Servers } |
              ForEach-Object { $_.RemoteAddress } | Select-Object -Unique
  } catch { }
  $s.ActiveDohSessions = if ($live) { $live -join ', ' } else { 'none seen' }

  [pscustomobject]$s
}

function Test-Resolution {
  # Deliberately several unrelated zones: one bad cached record or one dead
  # authoritative server must not read as "DNS is broken" and trigger a
  # needless rollback. Two of three passing is the bar.
  param([int]$TimeoutTries = 3)
  $names = @('microsoft.com', 'cloudflare.com', 'example.com')
  $ok = 0
  foreach ($n in $names) {
    for ($i = 0; $i -lt $TimeoutTries; $i++) {
      if (Resolve-DnsName $n -Type A -EA SilentlyContinue -QuickTimeout) { $ok++; break }
      Start-Sleep -Milliseconds 700
    }
  }
  [pscustomobject]@{ Passed = $ok; Total = $names.Count; Healthy = ($ok -ge 2) }
}

function Save-State {
  param([string]$Alias)
  if (-not (Test-Path $StateDir)) { New-Item $StateDir -ItemType Directory -Force | Out-Null }
  $ipif = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -EA SilentlyContinue
  $guid = (Get-NetAdapter -InterfaceAlias $Alias).InterfaceGuid
  $reg  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -EA SilentlyContinue
  [pscustomobject]@{
    SavedAt       = (Get-Date).ToString('s')
    Alias         = $Alias
    Guid          = "$guid"
    # NameServer empty = the adapter was on DHCP-supplied DNS. That is the
    # value the revert keys off, and it is why the revert works even if this
    # file is lost: "empty" is also the safe default.
    StaticServers = "$($reg.NameServer)"
    DhcpForIP     = "$($ipif.Dhcp)"
  } | ConvertTo-Json | Out-File $StateFile -Encoding utf8
  Write-Host "  Saved pre-change state to $StateFile" -ForegroundColor DarkGray
}

function Restore-Dhcp {
  param([string]$Alias)
  # -ResetServerAddresses clears the static list and lets DHCP repopulate it.
  # This is the safe default with or without a state file.
  Set-DnsClientServerAddress -InterfaceAlias $Alias -ResetServerAddresses -EA Stop
  Write-Host "  $Alias handed back to DHCP-supplied DNS" -ForegroundColor Green
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

$adapter = Resolve-TargetAdapter -Alias $InterfaceAlias
$alias   = $adapter.Name

# ------------------------------------------------------------------ status ---

Write-Host "`n==== DNS STATUS: $alias ====" -ForegroundColor Cyan
$before = Get-DnsStatus -Alias $alias
$before | Format-List

if (Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue) {
  Write-Host "  NOTE: a dead-man revert is armed. Run -Disarm once you are happy." -ForegroundColor Yellow
}

if ($PSCmdlet.ParameterSetName -eq 'Status') {
  Write-Host "Read-only check. Nothing changed." -ForegroundColor Yellow
  if ($before.WillEncrypt -eq 'none') {
    Write-Host "`nNo DNS traffic from this adapter is encrypted. To change that:" -ForegroundColor Yellow
    Write-Host "    .\Set-EncryptedDns.ps1 -Apply" -ForegroundColor Yellow
  } elseif ($before.WillBePlain -ne 'none') {
    Write-Host "`nMIXED: $($before.WillBePlain) is queried in CLEARTEXT." -ForegroundColor Red
    Write-Host "Re-run -Apply to drop back to resolvers that all auto-upgrade." -ForegroundColor Red
  } else {
    Write-Host "`nAll configured resolvers auto-upgrade to DoH." -ForegroundColor Green
  }
  return
}

# ------------------------------------------------------------------ revert ---

if ($Revert) {
  Write-Host "`n==== REVERT ====" -ForegroundColor Cyan

  if ($PSCmdlet.ShouldProcess($alias, 'Restore DHCP-supplied DNS servers')) {
    try { Restore-Dhcp -Alias $alias }
    catch { Write-Warning "  Could not reset $alias : $($_.Exception.Message)" }
  }

  # A state file that says the adapter HAD static servers before we touched it
  # means DHCP is not the right target - put the original list back instead.
  if (Test-Path $StateFile) {
    $st = Get-Content $StateFile -Raw | ConvertFrom-Json
    if ($st.Alias -eq $alias -and -not [string]::IsNullOrWhiteSpace($st.StaticServers)) {
      $orig = $st.StaticServers -split '[,\s]+' | Where-Object { $_ }
      if ($PSCmdlet.ShouldProcess($alias, "Restore original static servers: $($orig -join ', ')")) {
        Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $orig -EA SilentlyContinue
        Write-Host "  Restored the adapter's original static servers: $($orig -join ', ')" -ForegroundColor Green
      }
    }
  }

  if ($Full) {
    # Return the template table to stock. Kept behind a switch because on its
    # own it changes nothing about what the machine queries - it only matters
    # if the adapter is pointed at these servers.
    foreach ($d in @(
        @{ S = '1.1.1.1'; T = 'https://cloudflare-dns.com/dns-query' },
        @{ S = '8.8.8.8'; T = 'https://dns.google/dns-query' })) {
      if ($PSCmdlet.ShouldProcess($d.S, 'Reset DoH template flags to stock')) {
        netsh dns set encryption server=$($d.S) dohtemplate=$($d.T) autoupgrade=no udpfallback=no | Out-Null
        if ($LASTEXITCODE -eq 0) { "  $($d.S): auto-upgrade off (stock)" }
        else { Write-Warning "  Could not reset DoH flags for $($d.S) (exit $LASTEXITCODE)" }
      }
    }
    Write-Host "  Section D's registry opt-in (EnableAutoDoh) is Revert-FixGaps.ps1 -RepairDns' job." -ForegroundColor DarkGray
  }

  if ($PSCmdlet.ShouldProcess('Dnscache', 'Flush cache')) {
    ipconfig /flushdns | Out-Null
    "  DNS cache flushed"
  }

  Remove-DeadMan | Out-Null

  Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
  Get-DnsStatus -Alias $alias | Format-List
  $t = Test-Resolution
  if ($t.Healthy) { Write-Host "Resolution OK ($($t.Passed)/$($t.Total))." -ForegroundColor Green }
  else {
    Write-Host @"
Resolution STILL failing after revert ($($t.Passed)/$($t.Total)).
That means the problem is NOT the adapter's DNS servers - this script has
already handed them back. Escalate to the service-level repair:
    .\Revert-FixGaps.ps1 -RepairDns
and if that does not do it, reboot and run it again.
"@ -ForegroundColor Red
  }
  return
}

# ------------------------------------------------------------------- apply ---

Write-Host "`n==== APPLY: encrypted DNS on $alias ====" -ForegroundColor Cyan

# Refuse to point the adapter at a resolver that would go out in cleartext.
# Silently-unencrypted DNS is worse than none: it looks done and is not.
$tbl = Get-DnsClientDohServerAddress -EA SilentlyContinue
$bad = @()
foreach ($srv in $Servers) {
  $row = $tbl | Where-Object { $_.ServerAddress -eq $srv }
  if (-not $row) { $bad += "$srv (no DoH template on file)" }
  elseif (-not $row.AutoUpgrade) { $bad += "$srv (template exists but AutoUpgrade=False)" }
}
if ($bad) {
  Write-Host "  These would NOT be encrypted:" -ForegroundColor Red
  $bad | ForEach-Object { "    $_" }
  throw "Refusing to apply. Fix the template table first (Fix-Gaps.ps1 Section D), or pass -Servers that auto-upgrade."
}
Write-Host "  Verified: all of $($Servers -join ', ') auto-upgrade to DoH" -ForegroundColor Green

if ($ArmDeadMan -gt 0) {
  if ($PSCmdlet.ShouldProcess("scheduled task $TaskName", "Arm auto-revert in $ArmDeadMan minutes")) {
    Remove-DeadMan | Out-Null

    # Run the task from a copy on the OS drive, never from wherever this script
    # happens to live. The task runs as SYSTEM and may fire after a reboot; a
    # BitLocker-protected or removable volume is not guaranteed to be readable
    # at that moment, and a dead man that cannot start is worse than none
    # because you would be counting on it.
    $taskCopy = 'C:\SecureVault\Set-EncryptedDns.ps1'
    try {
      if (-not (Test-Path 'C:\SecureVault')) { New-Item 'C:\SecureVault' -ItemType Directory -Force | Out-Null }
      Copy-Item $PSCommandPath $taskCopy -Force -EA Stop
      Write-Host "  Dead-man will run from $taskCopy (always readable at boot)" -ForegroundColor DarkGray
    } catch {
      Write-Warning "  Could not stage a copy on C: ($($_.Exception.Message)) - falling back to $PSCommandPath"
      $taskCopy = $PSCommandPath
    }

    $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$taskCopy`" -Revert -InterfaceAlias `"$alias`""
    # A time trigger, not a startup trigger: this must fire whether or not the
    # machine reboots in the meantime.
    $trg = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($ArmDeadMan))
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Principal $pr `
                           -Description 'Auto-revert encrypted DNS if not disarmed' | Out-Null
    Write-Host "  DEAD MAN ARMED: reverts at $((Get-Date).AddMinutes($ArmDeadMan).ToString('HH:mm:ss')) unless you run -Disarm" -ForegroundColor Yellow
  }
}

Save-State -Alias $alias

if ($PSCmdlet.ShouldProcess($alias, "Set DNS servers to $($Servers -join ', ')")) {
  try {
    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $Servers -EA Stop
    Write-Host "  $alias -> $($Servers -join ', ')" -ForegroundColor Green
  } catch {
    Write-Warning "  Failed to set servers: $($_.Exception.Message)"
    Restore-Dhcp -Alias $alias
    throw "Apply failed and was rolled back."
  }

  ipconfig /flushdns | Out-Null

  # Give Dnscache a moment to discover the new servers and open its TLS
  # session before judging whether this worked.
  Start-Sleep -Seconds 3

  $t = Test-Resolution
  if (-not $t.Healthy) {
    Write-Host "`n  VERIFY FAILED ($($t.Passed)/$($t.Total)) - rolling back automatically." -ForegroundColor Red
    Restore-Dhcp -Alias $alias
    ipconfig /flushdns | Out-Null
    Start-Sleep -Seconds 2
    $t2 = Test-Resolution
    if ($t2.Healthy) {
      Write-Host "  Rolled back and resolution is working again ($($t2.Passed)/$($t2.Total))." -ForegroundColor Green
      Write-Host "  This network appears to block or intercept outbound DNS. Leave it on DHCP here." -ForegroundColor Yellow
    } else {
      Write-Host "  Rollback did not restore resolution either - the fault is deeper than the adapter." -ForegroundColor Red
      Write-Host "  Run: .\Revert-FixGaps.ps1 -RepairDns" -ForegroundColor Red
    }
    Remove-DeadMan | Out-Null
    return
  }
  Write-Host "  Resolution verified ($($t.Passed)/$($t.Total))" -ForegroundColor Green
}

Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
$after = Get-DnsStatus -Alias $alias
$after | Format-List

if ($after.ActiveDohSessions -eq 'none seen') {
  Write-Host @"
Config is correct but no TLS session to the resolvers is open yet. That is
normal immediately after applying - Windows opens one on the next uncached
lookup. Force one and re-check with:
    Resolve-DnsName "$((New-Guid).Guid).example.com" -EA SilentlyContinue
    .\Set-EncryptedDns.ps1
"@ -ForegroundColor Yellow
} else {
  Write-Host "DoH is live: encrypted session(s) open to $($after.ActiveDohSessions)" -ForegroundColor Green
}

Write-Host @"

If anything goes wrong from here:   .\Set-EncryptedDns.ps1 -Revert
On a captive-portal Wi-Fi:          .\Set-EncryptedDns.ps1 -Revert   (re-apply after login)
Service-level DNS failure:          .\Revert-FixGaps.ps1 -RepairDns
"@ -ForegroundColor Cyan
