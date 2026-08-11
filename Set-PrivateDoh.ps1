<#
    Set-PrivateDoh.ps1  -  your own DoH resolvers ONLY, with a watchdog that
                           restores public resolvers if they ever go dark.

    RUN IN AN ELEVATED (Administrator) PowerShell.

    WHY THIS SHAPE (measured 2026-08-07, not assumed)
    The first attempt listed all four servers on the adapter in priority order:
    yours first, 1.1.1.1/8.8.8.8 behind them. Windows ignored the order. With
    the registry NameServer value provably correct and no NRPT rule, Windows
    opened HTTP/2 sessions to all four at once and then spread queries across
    them - one 12-sample run went 12/12 to Google, a run ten minutes later went
    13/15 to Cloudflare and only 2/15 to the primary. Latency did not explain
    it (it preferred Google at 14 ms over Cloudflare at 6 ms).

    The Windows DNS client server list is a RESILIENCE POOL WITH ADAPTIVE
    SELECTION, NOT AN ORDERED PREFERENCE. There is no native knob for strict
    priority. So the only way to guarantee your servers are used is to be the
    only servers listed - and to move fallback out of the adapter and into a
    watchdog.

      adapter  ->  your primary + your secondary        (100% of queries)
                   each with AllowFallbackToUdp=True
      watchdog ->  swaps in 1.1.1.1 + 8.8.8.8 if both of yours go dark,
                   and swaps back once they answer again

    HOW RESOLUTION SURVIVES
      1. DoH to your two servers (this is the normal path)
      2. plain UDP/53 to those same two IPs, if DoH fails
      3. watchdog swaps the adapter to 1.1.1.1 + 8.8.8.8 (DoH, UDP fallback on)
      4. EnableAutoDoh stays 2 ("prefer"), never 3 ("require"), so no network
         can deny resolution outright

    THE TRADE YOU ACCEPTED
    Fallback is no longer instant. Between both your servers dying and the
    watchdog firing there is a window of up to -WatchdogMinutes (default 2)
    where DNS does not resolve. That includes every captive portal you join,
    until the watchdog notices and swaps. That is the price of tier-1 always
    being yours.

    ABOUT UDP FALLBACK ON YOUR SERVERS
    Enabled at your request. Be aware what it means: your endpoints
    authenticate you with the TOKEN IN THE URL PATH, which only exists over
    HTTPS. A UDP/53 query to the same IP carries no token, so it is an
    anonymous cleartext query answered by whatever is listening. On the network
    this was tested on, that is NOT your server: port 53 is intercepted in both
    directions - TCP/53 to both of your IPs, to 1.1.1.1, and to 203.0.113.7 (an
    address that physically cannot answer) all returned the same intercepting
    egress IP (e.g. 198.51.100.5), while HTTPS to your endpoints returned their own
    IPs. So here, tier 2 resolves via the local interceptor, in the clear.
    It keeps DNS working. It gives you no privacy and no authentication.
    Re-check with -Status on a network you trust.

    THIS DOES NOT TOUCH the Dnscache service key. That key - specifically
    'New-Item -Force' on it, which deletes and recreates it empty and wipes
    ServiceDll - is what actually broke DNS on 2026-08-06. DoH was blamed and
    was not responsible. Nothing here goes near it.

    MODES
      (no switches)   Read-only status: what is configured, what is encrypted,
                      and which resolver is actually serving queries.
      -Apply          Register templates, point the adapter at your servers
                      only, install the watchdog, verify, auto-roll-back on
                      failure.
      -Refresh        Re-resolve the endpoint hostnames and re-pin if their IPs
                      moved. Safe on a schedule. See PINNING.
      -Watchdog       One health check + swap decision. This is what the
                      scheduled task runs. Logs, prints nothing.
      -Revert         Adapter back to 1.1.1.1 + 8.8.8.8 DoH; watchdog removed;
                      your templates removed.
      -ToDhcp         With -Revert, hand DNS wholly back to DHCP instead. The
                      captive-portal escape hatch.
      -ArmDeadMan N   One-shot task that runs -Revert in N minutes unless
                      -Disarm first. Survives a reboot.
      -Disarm         Cancel the dead-man task.

      -DohFile        Path to a small text file holding your two endpoint URLs.
                      Single source of truth for those URLs - deliberately NOT
                      copied into this script, because those URLs contain bearer
                      tokens. Keep this file OUTSIDE any folder that is synced to
                      the cloud or backed up off-machine (the vault backup tree,
                      OneDrive, etc.), so the tokens never leave the device.
      -RescueServers  What the watchdog falls back to. Default 1.1.1.1,8.8.8.8.
      -WatchdogMinutes  Check interval, default 2. This is also your worst-case
                      DNS outage.
      -SkipIPv6       Leave IPv6 DNS alone (see IPV6 below).

    PINNING (the one real fragility)
    Windows binds a DoH template to a server IP, not a hostname - it dials the
    IP and validates the cert against the template's hostname. No bootstrap
    problem, but the IP is pinned at apply time. If your provider renumbers,
    both your servers go dark and the watchdog parks you on 1.1.1.1/8.8.8.8
    until you run -Refresh. Both hostnames are single-A on dedicated IPs today,
    no CDN, so this should be rare.

    IPV6
    Your endpoints publish no AAAA, so they cannot serve IPv6. Leaving IPv6 DNS
    on DHCP would let any IPv6 network hand Windows its own resolver and
    bypass everything above. Apply therefore sets IPv6 DNS to an explicitly
    EMPTY static list (netsh 'address=none'), which stops Windows using any
    IPv6 resolver without disturbing IPv6 addressing or routing. Suppress with
    -SkipIPv6.

    Supports -WhatIf on every mutation.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Apply')]    [switch]$Apply,
  [Parameter(ParameterSetName = 'Refresh')]  [switch]$Refresh,
  [Parameter(ParameterSetName = 'Watchdog')] [switch]$Watchdog,
  [Parameter(ParameterSetName = 'InstallWatchdog')] [switch]$InstallWatchdog,
  [Parameter(ParameterSetName = 'Revert')]   [switch]$Revert,
  [Parameter(ParameterSetName = 'Revert')]   [switch]$ToDhcp,
  [Parameter(ParameterSetName = 'Disarm')]   [switch]$Disarm,
  [string]$InterfaceAlias,
  [string]$DohFile = 'C:\SecureVault\doh',
  [string[]]$RescueServers = @('1.1.1.1', '8.8.8.8'),
  [int]$WatchdogMinutes = 2,
  [switch]$SkipIPv6,
  [int]$ArmDeadMan = 0
)

$ErrorActionPreference = 'Continue'

# powershell.exe -File binds "-RescueServers 1.1.1.1,8.8.8.8" as ONE string
# containing a comma, NOT a two-element array - verified, not assumed. The
# watchdog is launched exactly that way by the scheduled task, so without this
# it would try to set the adapter's DNS to a single bogus server named
# "1.1.1.1,8.8.8.8" and the rescue would fail at the one moment it is needed.
# Normalising here covers both invocation styles.
$RescueServers = @($RescueServers |
                     ForEach-Object { $_ -split ',' } |
                     ForEach-Object { $_.Trim() } |
                     Where-Object { $_ })

$StateDir     = 'C:\SecureVault\Backups'
$StateFile    = Join-Path $StateDir 'dns-privatedoh-lastgood.json'
$LogDir       = 'C:\SecureVault\Logs'
$LogFile      = Join-Path $LogDir 'doh-watchdog.log'
$DeadManTask  = 'SecureVault-PrivateDoh-DeadMan'
$WatchdogTask = 'SecureVault-DNS-Watchdog'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

# ---------------------------------------------------------------- helpers ----

function Write-Log {
  param([string]$Message)
  if (-not (Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
  "$((Get-Date).ToString('s'))  $Message" | Add-Content -Path $LogFile -Encoding utf8
}

function Get-Endpoint {
  <#
    Parses the endpoint list out of $DohFile. The file is prose-ish ("Primary",
    blank lines, a URL, "Secondary", ...), so we key off the only unambiguous
    thing in it: lines that are https:// URLs, in document order.
  #>
  param([string]$Path)

  if (-not (Test-Path $Path)) { throw "Endpoint file '$Path' not found. Pass -DohFile." }

  $urls = @(Get-Content $Path -EA Stop |
              ForEach-Object { $_.Trim() } |
              Where-Object { $_ -match '^https://\S+$' })

  if ($urls.Count -lt 1) { throw "No https:// endpoint URLs found in '$Path'." }
  if ($urls.Count -gt 2) { Write-Warning "  '$Path' lists $($urls.Count) URLs; using the first two." }

  $labels = @('primary', 'secondary')
  $i = 0
  foreach ($u in ($urls | Select-Object -First 2)) {
    $epHost = ([Uri]$u).Host        # NOT $host - that is a reserved automatic variable
    [pscustomobject]@{
      Rank     = $i + 1
      Label    = $labels[$i]
      Template = $u
      Hostname = $epHost
      Address  = $null              # filled by the template table or a lookup
    }
    $i++
  }
}

function Resolve-EndpointIp {
  <#
    Resolve an endpoint hostname to one IPv4 address using the RESCUE resolvers
    explicitly. We must not ask whatever the adapter currently points at - that
    may be the very server whose address we are trying to re-learn, or nothing
    at all if we are recovering from an outage.
  #>
  param([string]$Hostname)

  foreach ($srv in @($RescueServers) + @($null)) {
    try {
      $p = @{ Name = $Hostname; Type = 'A'; ErrorAction = 'Stop'; QuickTimeout = $true }
      if ($srv) { $p.Server = $srv; $p.DnsOnly = $true }
      $ips = @(Resolve-DnsName @p | Where-Object { $_.QueryType -eq 'A' } | ForEach-Object IPAddress)
      if ($ips) { return $ips[0] }
    } catch { }
  }
  $null
}

function Test-DohAlive {
  <#
    Cheap liveness probe: one real RFC 8484 POST, pinned to the IP with
    --resolve so the cert is validated the way Windows validates it, and NO
    dependency on name resolution already working. Returns $true only if the
    DNS payload itself is sane - a 200 carrying SERVFAIL is not alive.
    Used by the watchdog, which must be fast and must run when DNS is down.
  #>
  param([string]$Address, [string]$Hostname, [string]$Template, [int]$TimeoutSec = 8)

  $wire = [Convert]::FromBase64String('AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB')
  $qf = Join-Path $env:TEMP "dq-$PID.bin"
  $rf = Join-Path $env:TEMP "dr-$PID.bin"
  try {
    [IO.File]::WriteAllBytes($qf, $wire)
    & curl.exe -s --resolve "${Hostname}:443:${Address}" -o $rf `
        -H 'content-type: application/dns-message' -H 'accept: application/dns-message' `
        --data-binary "@$qf" $Template --max-time $TimeoutSec | Out-Null
    if (-not (Test-Path $rf)) { return $false }
    $b = [IO.File]::ReadAllBytes($rf)
    if ($b.Length -lt 12) { return $false }
    return ((($b[3] -band 0x0F) -eq 0) -and ((($b[6] -shl 8) + $b[7]) -ge 1))
  } catch { return $false }
  finally { Remove-Item $qf, $rf -Force -EA SilentlyContinue }
}

function Test-DohEndpoint {
  <#
    Full pre-flight, used by -Apply / -Refresh only. Windows' DoH client is
    strict in two ways a browser is not:
      1. it speaks HTTP/2 ONLY - an HTTP/1.1-only server fails
      2. it dials the IP and validates the cert against the template hostname
    Windows' bundled curl.exe has no HTTP/2 support at all, so it CANNOT test
    point 1 - it reports 1.1 for everything. Python's ssl module can, via ALPN.
  #>
  param([string]$Address, [string]$Hostname, [string]$Template)

  $alpn = $null
  $tcp  = $null
  try {
    $tcp = New-Object Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect($Address, 443, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(6000)) { throw "TCP 443 timeout" }
    $tcp.EndConnect($iar)
  } catch {
    Write-Host "      TLS/443 to $Address failed: $($_.Exception.Message)" -ForegroundColor Red
    return $false
  } finally { if ($tcp) { $tcp.Close() } }

  $py = @('C:\Python313\python.exe', 'python.exe') |
          ForEach-Object { (Get-Command $_ -EA SilentlyContinue).Source } |
          Select-Object -First 1
  if ($py) {
    $probe = @"
import socket, ssl
c = ssl.create_default_context(); c.set_alpn_protocols(['h2','http/1.1'])
with socket.create_connection(('$Address',443),timeout=8) as r:
    with c.wrap_socket(r, server_hostname='$Hostname') as s:
        print(s.selected_alpn_protocol() or 'none')
"@
    $tmp = Join-Path $env:TEMP "alpn-$PID.py"
    $probe | Out-File $tmp -Encoding utf8
    $alpn = (& $py $tmp 2>$null | Select-Object -Last 1)
    Remove-Item $tmp -Force -EA SilentlyContinue
  }
  if ($alpn -and $alpn -ne 'h2') {
    Write-Host "      ALPN negotiated '$alpn', not h2 - Windows DoH requires HTTP/2." -ForegroundColor Red
    return $false
  }

  if (Test-DohAlive -Address $Address -Hostname $Hostname -Template $Template -TimeoutSec 10) {
    Write-Host "      OK  alpn=$(if($alpn){$alpn}else{'unverified'})  DoH answers correctly" -ForegroundColor Green
    return $true
  }
  Write-Host "      DoH probe failed (no answer, bad rcode, or empty answer section)" -ForegroundColor Red
  return $false
}

function Set-DohTemplate {
  <#
    Register or update one entry in Windows' DoH template table.

    Add- vs Set- is not cosmetic: 1.1.1.1 / 8.8.8.8 / 9.9.9.9 already ship in
    the built-in table, Add- fails on them, and the netsh equivalent
    ('netsh dns add encryption') is a SILENT no-op on a server that already has
    an entry - it reports success and changes nothing. So probe, then branch.
  #>
  # Its own SupportsShouldProcess rather than borrowing the script's $PSCmdlet
  # through the scope chain: that works at runtime but trips PSShouldProcess
  # analysis. -WhatIf still propagates here via $WhatIfPreference.
  [CmdletBinding(SupportsShouldProcess)]
  param([string]$Address, [string]$Template, [bool]$UdpFallback)

  $existing = Get-DnsClientDohServerAddress -ServerAddress $Address -EA SilentlyContinue
  $verb     = if ($existing) { 'Update' } else { 'Add' }

  if (-not $PSCmdlet.ShouldProcess($Address, "$verb DoH template ($Template, udpFallback=$UdpFallback)")) { return }

  try {
    if ($existing) {
      Set-DnsClientDohServerAddress -ServerAddress $Address -DohTemplate $Template `
        -AutoUpgrade:$true -AllowFallbackToUdp:$UdpFallback -EA Stop
    } else {
      Add-DnsClientDohServerAddress -ServerAddress $Address -DohTemplate $Template `
        -AutoUpgrade:$true -AllowFallbackToUdp:$UdpFallback -EA Stop
    }
    Write-Host "    $verb`t$Address`tudpFallback=$UdpFallback" -ForegroundColor Green
  } catch {
    throw "Could not $verb DoH template for $Address : $($_.Exception.Message)"
  }
}

function Test-Resolution {
  # Three unrelated zones: one dead authoritative server or one poisoned cache
  # entry must not read as "DNS is broken" and trigger a needless swap.
  # Two of three is the bar.
  param([int]$Tries = 3)
  $names = @('microsoft.com', 'cloudflare.com', 'example.com')
  $ok = 0
  foreach ($n in $names) {
    for ($i = 0; $i -lt $Tries; $i++) {
      if (Resolve-DnsName $n -Type A -EA SilentlyContinue -QuickTimeout) { $ok++; break }
      Start-Sleep -Milliseconds 700
    }
  }
  [pscustomobject]@{ Passed = $ok; Total = $names.Count; Healthy = ($ok -ge 2) }
}

function Set-AdapterServers {
  param([string]$Alias, [string[]]$Servers)
  Set-DnsClientServerAddress -InterfaceAlias $Alias -ServerAddresses $Servers -EA Stop
  ipconfig /flushdns | Out-Null
}

function Clear-IPv6Dns {
  <#
    An explicitly EMPTY static IPv6 DNS list. Not the same as resetting to
    DHCP, which would let a router advertisement hand Windows a resolver and
    bypass the whole IPv4 chain. Static-and-empty means Windows has no IPv6
    resolver to use, while IPv6 addressing and routing carry on untouched.

    Done with netsh because Set-DnsClientServerAddress has NO -AddressFamily
    parameter, and its -ResetServerAddresses clears BOTH families - which here
    would wipe the IPv4 list we just set.
  #>
  param([string]$Alias)
  netsh interface ipv6 set dnsservers name="$Alias" source=static address=none validate=no | Out-Null
  return ($LASTEXITCODE -eq 0)
}

function Get-DohStatus {
  param([string]$Alias, [object[]]$Endpoints)

  $s = [ordered]@{}
  $s.Adapter = $Alias

  $v4 = Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv4 -EA SilentlyContinue
  $v6 = Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv6 -EA SilentlyContinue
  $s.IPv4Servers = if ($v4.ServerAddresses) { $v4.ServerAddresses -join ', ' } else { '<none>' }
  $s.IPv6Servers = if ($v6.ServerAddresses) { $v6.ServerAddresses -join ', ' } else { '<none - good>' }

  # Get-DnsClientServerAddress reports servers in USE but cannot say who chose
  # them. The interface's NameServer registry value can: it holds the static
  # list and is empty under DHCP. "We configured this" vs "the hotel router
  # did" is the distinction that matters after joining a new network.
  $guid = (Get-NetAdapter -InterfaceAlias $Alias -EA SilentlyContinue).InterfaceGuid
  $reg  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -EA SilentlyContinue
  $s.DnsIsStatic = -not [string]::IsNullOrWhiteSpace($reg.NameServer)

  $mine = @($Endpoints | Where-Object { $_.Address } | ForEach-Object Address)
  $cur  = @($v4.ServerAddresses)
  $s.ServingTier = if ($mine -and -not (@($cur | Where-Object { $_ -notin $mine }).Count)) { 'YOURS (tier 1)' }
                   elseif (@($cur | Where-Object { $_ -in $RescueServers }).Count)         { 'RESCUE - watchdog has failed over' }
                   else                                                                     { 'unknown / DHCP' }

  $tbl = Get-DnsClientDohServerAddress -EA SilentlyContinue
  $enc = @(); $plain = @()
  foreach ($srv in $cur) {
    if (-not $srv) { continue }
    $row = $tbl | Where-Object { $_.ServerAddress -eq $srv }
    if ($row -and $row.AutoUpgrade) { $enc += $srv } else { $plain += $srv }
  }
  $s.WillEncrypt = if ($enc)   { $enc   -join ', ' } else { 'none' }
  $s.WillBePlain = if ($plain) { $plain -join ', ' } else { 'none' }

  $s.EnableAutoDoh = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -EA SilentlyContinue).EnableAutoDoh
  if ($null -eq $s.EnableAutoDoh) { $s.EnableAutoDoh = '<not set>' }
  $s.DohMode = switch ("$($s.EnableAutoDoh)") {
    '2'     { 'prefer DoH, fall back (resolution cannot be locked out)' }
    '3'     { 'REQUIRE DoH - no fallback. Not what this script sets.' }
    default { 'auto-upgrade off' }
  }

  $wd = Get-ScheduledTask -TaskName $WatchdogTask -EA SilentlyContinue
  $s.WatchdogInstalled = if ($wd) { "yes ($($wd.State))" } else { 'NO - no automatic fallback!' }

  $s.Resolves = [bool](Resolve-DnsName microsoft.com -EA SilentlyContinue -QuickTimeout)

  # The only honest proof of what is carrying traffic: the DNS Client's host
  # process holding established TCP/443 sockets. Config says "should"; this
  # says "is".
  $live = @()
  try {
    $svcPids = (Get-CimInstance Win32_Service -Filter "Name='Dnscache'" -EA Stop).ProcessId
    $live = Get-NetTCPConnection -State Established -RemotePort 443 -OwningProcess $svcPids -EA SilentlyContinue |
              ForEach-Object { $_.RemoteAddress } | Select-Object -Unique
  } catch { }
  $names = @{}
  foreach ($e in $Endpoints) { if ($e.Address) { $names[$e.Address] = "$($e.Hostname) (YOURS)" } }
  $names['1.1.1.1'] = 'cloudflare (rescue)'
  $names['8.8.8.8'] = 'google (rescue)'
  $s.ActiveDohSessions = if ($live) {
    ($live | ForEach-Object { if ($names[$_]) { "$_ = $($names[$_])" } else { $_ } }) -join '; '
  } else { 'none seen' }

  [pscustomobject]$s
}

function Save-State {
  param([string]$Alias)
  if (-not (Test-Path $StateDir)) { New-Item $StateDir -ItemType Directory -Force | Out-Null }
  $guid = (Get-NetAdapter -InterfaceAlias $Alias).InterfaceGuid
  $reg  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -EA SilentlyContinue
  $v6   = Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv6 -EA SilentlyContinue
  [pscustomobject]@{
    SavedAt         = (Get-Date).ToString('s')
    Alias           = $Alias
    Guid            = "$guid"
    # Empty = the adapter was on DHCP-supplied DNS. That is what -Revert keys
    # off, and it is why revert still works if this file is lost: "empty" is
    # also the safe default.
    StaticServersV4 = "$($reg.NameServer)"
    ServersV6       = @($v6.ServerAddresses)
  } | ConvertTo-Json | Out-File $StateFile -Encoding utf8
  Write-Host "  Saved pre-change state to $StateFile" -ForegroundColor DarkGray
}

function Resolve-TargetAdapter {
  param([string]$Alias)
  if ($Alias) {
    $a = Get-NetAdapter -InterfaceAlias $Alias -EA SilentlyContinue
    if (-not $a) { throw "No adapter named '$Alias'. Adapters: $((Get-NetAdapter | ForEach-Object Name) -join ', ')" }
    return $a
  }
  # Sort on Speed (uint64), NOT LinkSpeed - LinkSpeed is a display string like
  # "459 Mbps" and sorts lexically, ranking 9 Mbps above 459 Mbps.
  $cand = Get-NetAdapter -Physical -EA SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' } | Sort-Object Speed -Descending
  if (-not $cand) { throw "No connected physical adapter found. Pass -InterfaceAlias explicitly." }
  $cand | Select-Object -First 1
}

function Remove-Task {
  param([string]$Name)
  if (Get-ScheduledTask -TaskName $Name -EA SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    Write-Host "  Task '$Name' removed" -ForegroundColor Green
    return $true
  }
  $false
}

function Get-PinnedAddress {
  # Recover each endpoint's currently-pinned IP from the template table, so
  # status and the watchdog work without doing any lookups.
  param([object[]]$Endpoints)
  $tbl = Get-DnsClientDohServerAddress -EA SilentlyContinue
  foreach ($e in $Endpoints) {
    $row = $tbl | Where-Object { $_.DohTemplate -eq $e.Template } | Select-Object -First 1
    if ($row) { $e.Address = $row.ServerAddress }
  }
  $Endpoints
}

function Install-Watchdog {
  <#
    The watchdog is the ONLY fallback now that the adapter lists nothing but
    your servers. If registration fails silently the machine sits one outage
    away from having no DNS at all - so this registers, then VERIFIES the task
    is really there, and falls back to schtasks.exe if the CIM cmdlet refuses.
  #>
  param([string]$Alias)

  Remove-Task -Name $WatchdogTask | Out-Null

  # Run from C:, not S:. The watchdog must start at boot before any removable
  # or BitLocker-protected volume is guaranteed readable - it is the thing that
  # rescues DNS, so it cannot depend on S: being mounted.
  $wdCopy = 'C:\SecureVault\Set-PrivateDoh.ps1'
  try {
    if (-not (Test-Path 'C:\SecureVault')) { New-Item 'C:\SecureVault' -ItemType Directory -Force | Out-Null }
    Copy-Item $PSCommandPath $wdCopy -Force -EA Stop
    # The endpoint file lives on S: and the watchdog needs it to probe.
    Copy-Item $DohFile 'C:\SecureVault\doh' -Force -EA Stop
    Write-Host "    Staged $wdCopy + C:\SecureVault\doh" -ForegroundColor DarkGray
  } catch {
    Write-Warning "    Could not stage on C: ($($_.Exception.Message)) - will run from $PSCommandPath and fail whenever S: is absent."
    $wdCopy = $PSCommandPath
  }
  $wdDoh = if (Test-Path 'C:\SecureVault\doh') { 'C:\SecureVault\doh' } else { $DohFile }

  # None of these paths contain spaces, so the argument line needs no inner
  # quoting - which is exactly what lets the schtasks fallback work without
  # quote-escaping gymnastics.
  $argLine = "-NoProfile -ExecutionPolicy Bypass -File $wdCopy -Watchdog -DohFile $wdDoh -RescueServers $($RescueServers -join ',')"

  try {
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
    # Two triggers: repeating for steady state, and at-startup so a machine
    # that boots onto a network where your servers are unreachable recovers
    # without you having to log in.
    $trgRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                   -RepetitionInterval (New-TimeSpan -Minutes $WatchdogMinutes)
    $trgBoot   = New-ScheduledTaskTrigger -AtStartup
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # Do NOT stop on battery - this laptop travels and the watchdog matters
    # most when unplugged on someone else's Wi-Fi.
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
             -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $WatchdogTask -Action $act -Trigger @($trgRepeat, $trgBoot) `
                           -Principal $pr -Settings $set -Force -EA Stop `
                           -Description 'Restores public DNS resolvers if the private DoH servers go dark, and returns to them when they recover' | Out-Null
  } catch {
    Write-Warning "    Register-ScheduledTask failed: $($_.Exception.Message)"
    Write-Host   "    Falling back to schtasks.exe..." -ForegroundColor Yellow
    schtasks.exe /Create /TN $WatchdogTask /TR "powershell.exe $argLine" `
                 /SC MINUTE /MO $WatchdogMinutes /RU SYSTEM /RL HIGHEST /F | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "    schtasks.exe also failed (exit $LASTEXITCODE)" }
  }

  # Verify, never assume. This is the whole safety net.
  $wd = Get-ScheduledTask -TaskName $WatchdogTask -EA SilentlyContinue
  if ($wd) {
    Write-Host "    Watchdog verified present: every $WatchdogMinutes min (state $($wd.State))" -ForegroundColor Green
    Write-Log "WATCHDOG INSTALLED: every $WatchdogMinutes min; rescue = $($RescueServers -join ', ')."
    return $true
  }

  Write-Host ""
  Write-Host "  ############### WATCHDOG NOT INSTALLED ###############" -ForegroundColor Red
  Write-Host "  The adapter now lists ONLY your servers, so there is currently" -ForegroundColor Red
  Write-Host "  NO fallback. If both go dark, DNS stops until you fix it by hand." -ForegroundColor Red
  Write-Host "  Retry:     .\Set-PrivateDoh.ps1 -InstallWatchdog" -ForegroundColor Red
  Write-Host "  Back out:  .\Set-PrivateDoh.ps1 -Revert" -ForegroundColor Red
  Write-Host "  ######################################################" -ForegroundColor Red
  Write-Log "WATCHDOG INSTALL FAILED - no DNS fallback in place."
  return $false
}

# ------------------------------------------------------------------ disarm ---

if ($Disarm) {
  Write-Host "`n==== DISARM ====" -ForegroundColor Cyan
  if (-not (Remove-Task -Name $DeadManTask)) { Write-Host "  No dead-man task was armed." -ForegroundColor Yellow }
  return
}

# ---------------------------------------------------------------- watchdog ---
# Runs headless as SYSTEM every -WatchdogMinutes. This is the ONLY thing
# standing between "both your servers died" and "no DNS", so it is deliberately
# dumb: probe, decide, swap, log. No console output.

if ($Watchdog) {
  try {
    $adapter = Resolve-TargetAdapter -Alias $InterfaceAlias
  } catch {
    # No adapter up - nothing to do, and definitely nothing to swap. Silence is
    # correct here: a laptop with the lid shut is not a DNS fault.
    return
  }
  $alias = $adapter.Name

  $eps = Get-PinnedAddress -Endpoints @(Get-Endpoint -Path $DohFile)
  $mine = @($eps | Where-Object { $_.Address } | ForEach-Object Address)
  if (-not $mine) { Write-Log "WATCHDOG: no endpoints pinned in the template table - has -Apply run? Doing nothing."; return }

  $cur      = @((Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 -EA SilentlyContinue).ServerAddresses)
  $onMine   = ($cur.Count -gt 0) -and -not (@($cur | Where-Object { $_ -notin $mine }).Count)
  $onRescue = ($cur.Count -gt 0) -and -not (@($cur | Where-Object { $_ -notin $RescueServers }).Count)

  if ($onMine) {
    if ((Test-Resolution -Tries 1).Healthy) { return }        # normal case, cheap, silent
    # Re-test once before acting. A single blip - a roaming Wi-Fi handoff, a
    # suspended radio - must not trigger a swap.
    Start-Sleep -Seconds 3
    if ((Test-Resolution -Tries 2).Healthy) { return }

    Write-Log "WATCHDOG: resolution failing on your servers ($($cur -join ', ')). Swapping to rescue $($RescueServers -join ', ')."
    try {
      Set-AdapterServers -Alias $alias -Servers $RescueServers
      Start-Sleep -Seconds 2
      $t = Test-Resolution -Tries 2
      Write-Log "WATCHDOG: rescue applied. Resolution $($t.Passed)/$($t.Total)."
    } catch { Write-Log "WATCHDOG: FAILED to apply rescue - $($_.Exception.Message)" }
    return
  }

  if ($onRescue) {
    # Parked on the rescue servers. Come back the moment either of yours
    # answers a real DoH query - probing the endpoint directly, not via
    # Windows, so this works regardless of what the resolver is doing.
    $alive = @($eps | Where-Object { $_.Address -and (Test-DohAlive -Address $_.Address -Hostname $_.Hostname -Template $_.Template -TimeoutSec 6) })
    if (-not $alive) { return }

    Write-Log "WATCHDOG: $($alive.Count) of your endpoint(s) answering again. Swapping back."
    try {
      Set-AdapterServers -Alias $alias -Servers @($alive | Sort-Object Rank | ForEach-Object Address)
      Start-Sleep -Seconds 2
      $t = Test-Resolution -Tries 2
      if ($t.Healthy) {
        Write-Log "WATCHDOG: back on your servers. Resolution $($t.Passed)/$($t.Total)."
      } else {
        # Probe said alive, Windows disagrees. Rescue is the safe place to sit.
        Set-AdapterServers -Alias $alias -Servers $RescueServers
        Write-Log "WATCHDOG: swap-back verify FAILED ($($t.Passed)/$($t.Total)) - returned to rescue."
      }
    } catch { Write-Log "WATCHDOG: swap-back error - $($_.Exception.Message)" }
    return
  }

  # Neither set: something else owns DNS (DHCP after a -Revert -ToDhcp, or a
  # VPN). Not ours to fight over.
  return
}

# ------------------------------------------------------------------ status ---

$adapter   = Resolve-TargetAdapter -Alias $InterfaceAlias
$alias     = $adapter.Name
$endpoints = @()
try { $endpoints = @(Get-Endpoint -Path $DohFile) }
catch { if ($Apply -or $Refresh) { throw } else { Write-Warning $_.Exception.Message } }
$endpoints = @(Get-PinnedAddress -Endpoints $endpoints)

Write-Host "`n==== DoH STATUS: $alias ====" -ForegroundColor Cyan
foreach ($e in $endpoints) {
  $pin = if ($e.Address) { $e.Address } else { '<not registered>' }
  Write-Host ("  {0,-10} {1,-22} -> {2}" -f $e.Label, $e.Hostname, $pin) -ForegroundColor DarkGray
}
$before = Get-DohStatus -Alias $alias -Endpoints $endpoints
$before | Format-List

if (Get-ScheduledTask -TaskName $DeadManTask -EA SilentlyContinue) {
  Write-Host "  NOTE: a dead-man revert is armed. Run -Disarm once you are happy." -ForegroundColor Yellow
}

if ($PSCmdlet.ParameterSetName -eq 'Status') {
  Write-Host "Read-only check. Nothing changed." -ForegroundColor Yellow
  if (Test-Path $LogFile) {
    Write-Host "`n  Last watchdog activity:" -ForegroundColor Cyan
    Get-Content $LogFile -Tail 5 | ForEach-Object { "    $_" }
  }
  Write-Host "`nTo build it:   .\Set-PrivateDoh.ps1 -Apply" -ForegroundColor Cyan
  return
}

# -------------------------------------------------------- install watchdog ---
# Repair path: re-install just the watchdog without touching the adapter. For
# when -Apply set the resolvers correctly but task registration failed, which
# leaves the machine with no fallback at all.

if ($InstallWatchdog) {
  Write-Host "`n==== INSTALL WATCHDOG ====" -ForegroundColor Cyan
  $ok = Install-Watchdog -Alias $alias
  if ($ok) { Write-Host "`nFallback is in place again." -ForegroundColor Green }
  return
}

# ------------------------------------------------------------------ revert ---

if ($Revert) {
  Write-Host "`n==== REVERT ====" -ForegroundColor Cyan

  Remove-Task -Name $WatchdogTask | Out-Null

  if ($ToDhcp) {
    # Captive-portal escape hatch. -ResetServerAddresses clears both families
    # and lets DHCP repopulate - always a safe landing.
    if ($PSCmdlet.ShouldProcess($alias, 'Hand DNS back to DHCP')) {
      try {
        Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses -EA Stop
        Write-Host "  $alias handed back to DHCP-supplied DNS" -ForegroundColor Green
      } catch { Write-Warning "  Could not reset $alias : $($_.Exception.Message)" }
    }
  } else {
    if ($PSCmdlet.ShouldProcess($alias, "Restore $($RescueServers -join ', ')")) {
      try {
        Set-AdapterServers -Alias $alias -Servers $RescueServers
        Write-Host "  $alias -> $($RescueServers -join ', ')" -ForegroundColor Green
      } catch { Write-Warning "  Could not set servers: $($_.Exception.Message)" }
    }
    # Restore IPv6 to whatever it was before Apply emptied it.
    #
    # NOTE: -ResetServerAddresses has NO address-family parameter - it resets
    # BOTH families. Using it here to clear IPv6 would also wipe the IPv4 list
    # set two lines above. So the "was empty" case goes through netsh, the only
    # way to hand back one family on its own.
    if (Test-Path $StateFile) {
      $st = Get-Content $StateFile -Raw | ConvertFrom-Json
      if ($st.Alias -eq $alias -and $PSCmdlet.ShouldProcess($alias, 'Restore prior IPv6 DNS')) {
        try {
          if ($st.ServersV6) {
            Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses @($st.ServersV6) -EA Stop
            Write-Host "  IPv6 DNS restored to $(@($st.ServersV6) -join ', ')" -ForegroundColor Green
          } else {
            netsh interface ipv6 set dnsservers name="$alias" source=dhcp | Out-Null
            Write-Host "  IPv6 DNS handed back to DHCP (was unset before)" -ForegroundColor Green
          }
        } catch { Write-Warning "  IPv6 restore: $($_.Exception.Message)" }
      }
    }
  }

  # Drop the custom templates. An unused table entry resolves nothing on its
  # own, but it keeps your tokens sitting in the registry - so remove them.
  foreach ($e in $endpoints) {
    if (-not $e.Address) { continue }
    if ($PSCmdlet.ShouldProcess($e.Address, "Remove DoH template for $($e.Hostname)")) {
      try {
        Remove-DnsClientDohServerAddress -ServerAddress $e.Address -EA Stop
        Write-Host "  Removed template for $($e.Hostname) ($($e.Address))" -ForegroundColor Green
      } catch { Write-Warning "  Could not remove $($e.Address): $($_.Exception.Message)" }
    }
  }

  if ($PSCmdlet.ShouldProcess('Dnscache', 'Flush cache')) { ipconfig /flushdns | Out-Null; "  DNS cache flushed" }
  Remove-Task -Name $DeadManTask | Out-Null

  Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
  Get-DohStatus -Alias $alias -Endpoints @() | Format-List
  $t = Test-Resolution
  if ($t.Healthy) { Write-Host "Resolution OK ($($t.Passed)/$($t.Total))." -ForegroundColor Green }
  else {
    Write-Host @"
Resolution STILL failing after revert ($($t.Passed)/$($t.Total)).
The fault is NOT this chain - it has already been dismantled. Escalate:
    .\Revert-FixGaps.ps1 -RepairDns
and if that does not do it, reboot and run it again.
"@ -ForegroundColor Red
  }
  return
}

# --------------------------------------------------------- apply / refresh ---

$mode = if ($Refresh) { 'REFRESH' } else { 'APPLY' }
Write-Host "`n==== $mode : your resolvers only, on $alias ====" -ForegroundColor Cyan

Write-Host "`n  Resolving and probing your endpoints..." -ForegroundColor Cyan
$usable = @()
foreach ($e in $endpoints) {
  $ip = Resolve-EndpointIp -Hostname $e.Hostname
  if (-not $ip) { Write-Host "    $($e.Label) $($e.Hostname): NO A RECORD - skipping" -ForegroundColor Red; continue }
  $moved = $e.Address -and ($e.Address -ne $ip)
  Write-Host "    $($e.Label) $($e.Hostname) -> $ip$(if($moved){" (MOVED from $($e.Address))"})" -ForegroundColor $(if($moved){'Yellow'}else{'Gray'})
  if (Test-DohEndpoint -Address $ip -Hostname $e.Hostname -Template $e.Template) {
    $e.Address = $ip
    $usable += $e
  } else {
    Write-Host "    $($e.Label): probe FAILED - will not be used" -ForegroundColor Red
  }
}

if (-not $usable) {
  Write-Host "`n  Neither of your endpoints is usable right now." -ForegroundColor Red
  Write-Host "  Refusing to change anything - that would leave you with no resolver at all." -ForegroundColor Yellow
  return
}
Write-Host "`n  $($usable.Count) of $($endpoints.Count) endpoint(s) usable." -ForegroundColor Green
if ($usable.Count -eq 1) {
  Write-Host "  WARNING: only one of your servers is answering. No redundancy until the" -ForegroundColor Yellow
  Write-Host "  other returns - the watchdog is your only safety net. Re-run -Refresh later." -ForegroundColor Yellow
}

if ($ArmDeadMan -gt 0) {
  if ($PSCmdlet.ShouldProcess("scheduled task $DeadManTask", "Arm auto-revert in $ArmDeadMan minutes")) {
    Remove-Task -Name $DeadManTask | Out-Null
    # Run from a copy on the OS drive, never from S:. The task runs as SYSTEM
    # and may fire after a reboot; a removable or BitLocker-protected volume is
    # not guaranteed readable at that moment, and a dead man that cannot start
    # is worse than none because you would be counting on it.
    $taskCopy = 'C:\SecureVault\Set-PrivateDoh.ps1'
    try {
      if (-not (Test-Path 'C:\SecureVault')) { New-Item 'C:\SecureVault' -ItemType Directory -Force | Out-Null }
      Copy-Item $PSCommandPath $taskCopy -Force -EA Stop
    } catch {
      Write-Warning "  Could not stage a copy on C: ($($_.Exception.Message)) - using $PSCommandPath"
      $taskCopy = $PSCommandPath
    }
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' `
             -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$taskCopy`" -Revert -InterfaceAlias `"$alias`""
    # A time trigger, not a startup trigger: this must fire whether or not the
    # machine reboots in the meantime.
    $trg = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($ArmDeadMan))
    $pr  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $DeadManTask -Action $act -Trigger $trg -Principal $pr `
                           -Description 'Auto-revert private DoH chain if not disarmed' | Out-Null
    Write-Host "  DEAD MAN ARMED: reverts at $((Get-Date).AddMinutes($ArmDeadMan).ToString('HH:mm:ss')) unless you run -Disarm" -ForegroundColor Yellow
  }
}

Save-State -Alias $alias

# --- template table --------------------------------------------------------
Write-Host "`n  Registering DoH templates..." -ForegroundColor Cyan
foreach ($e in $usable) {
  # UdpFallback TRUE at your request. See "ABOUT UDP FALLBACK" in the header -
  # a UDP/53 query to these IPs carries no token and, on a network that
  # intercepts port 53, does not reach your servers at all.
  Set-DohTemplate -Address $e.Address -Template $e.Template -UdpFallback $true
}
# Registered but NOT put on the adapter. These exist so that when the watchdog
# swaps them in, the rescue path is already encrypted with UDP fallback on.
foreach ($d in @(
    @{ S = '1.1.1.1'; T = 'https://cloudflare-dns.com/dns-query' },
    @{ S = '8.8.8.8'; T = 'https://dns.google/dns-query' })) {
  Set-DohTemplate -Address $d.S -Template $d.T -UdpFallback $true
}

# --- adapter: yours, and only yours ----------------------------------------
$order = @($usable | Sort-Object Rank | ForEach-Object Address)
Write-Host "`n  Setting adapter to YOUR servers only: $($order -join ', ')" -ForegroundColor Cyan

if ($PSCmdlet.ShouldProcess($alias, "Set IPv4 DNS to $($order -join ', ')")) {
  try {
    Set-AdapterServers -Alias $alias -Servers $order
  } catch {
    Write-Warning "  Failed to set servers: $($_.Exception.Message)"
    Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $RescueServers -EA SilentlyContinue
    throw "Apply failed; adapter returned to $($RescueServers -join ', ')."
  }

  if (-not $SkipIPv6) {
    if (Clear-IPv6Dns -Alias $alias) {
      Write-Host "  IPv6 DNS emptied (no IPv6 bypass; addressing untouched)" -ForegroundColor Green
    } else {
      Write-Warning "  Could not empty IPv6 DNS (netsh exit $LASTEXITCODE) - an IPv6 network could bypass this."
    }
  }

  # Give Dnscache a moment to notice the new servers and open its TLS session
  # before judging whether this worked.
  Start-Sleep -Seconds 3

  $t = Test-Resolution
  if (-not $t.Healthy) {
    Write-Host "`n  VERIFY FAILED ($($t.Passed)/$($t.Total)) - rolling back automatically." -ForegroundColor Red
    Set-AdapterServers -Alias $alias -Servers $RescueServers
    Start-Sleep -Seconds 2
    $t2 = Test-Resolution
    if ($t2.Healthy) {
      Write-Host "  Rolled back to $($RescueServers -join ', '); resolution works ($($t2.Passed)/$($t2.Total))." -ForegroundColor Green
      Write-Host "  Your endpoints probed OK but Windows will not resolve through them." -ForegroundColor Yellow
    } else {
      Write-Host "  Rollback did not restore resolution either - the fault is deeper than the adapter." -ForegroundColor Red
      Write-Host "  Run: .\Set-PrivateDoh.ps1 -Revert -ToDhcp   then   .\Revert-FixGaps.ps1 -RepairDns" -ForegroundColor Red
    }
    Remove-Task -Name $DeadManTask | Out-Null
    return
  }
  Write-Host "  Resolution verified ($($t.Passed)/$($t.Total))" -ForegroundColor Green
}

# --- watchdog --------------------------------------------------------------
# Installed LAST and only after resolution verified. Installing it before we
# know the config works would just have it fight the rollback.
Write-Host "`n  Installing watchdog (every $WatchdogMinutes min)..." -ForegroundColor Cyan
if ($PSCmdlet.ShouldProcess("scheduled task $WatchdogTask", "Install DNS watchdog every $WatchdogMinutes minutes")) {
  Install-Watchdog -Alias $alias | Out-Null
  Write-Log "APPLY: adapter set to $($order -join ', ')."
}

# --- prove it -------------------------------------------------------------
# Force an uncached lookup so Dnscache has to open a session, then look at who
# it opened it to. A GUID label guarantees a cache miss.
Resolve-DnsName "$((New-Guid).Guid).example.com" -EA SilentlyContinue -QuickTimeout | Out-Null
Start-Sleep -Seconds 2

Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
$after = Get-DohStatus -Alias $alias -Endpoints $usable
$after | Format-List

Write-Host @"

Adapter:   $($order -join ', ')   (yours, exclusively)
Fallback:  UDP/53 to those same IPs, then the watchdog swaps in $($RescueServers -join ' + ')
Worst case: up to $WatchdogMinutes min without DNS before the watchdog fires.

Verify which resolver is really serving you:
    Resolve-DnsName whoami.akamai.net -Type A
  Expect one of: $($order -join ', ') - anything else means you are on rescue.

Watchdog log:        C:\SecureVault\Logs\doh-watchdog.log
Re-pin moved IPs:    .\Set-PrivateDoh.ps1 -Refresh
If anything breaks:  .\Set-PrivateDoh.ps1 -Revert
On a captive portal: .\Set-PrivateDoh.ps1 -Revert -ToDhcp   (re-apply after login)
Service-level DNS failure: .\Revert-FixGaps.ps1 -RepairDns
"@ -ForegroundColor Cyan
