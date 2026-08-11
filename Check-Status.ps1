<#
    Check-Status.ps1  -  read-only health check for everything hardened on
                         2026-08-06. Changes nothing. Run it after a reboot.

    Run ELEVATED for the full picture: mapping a TCP socket to the Dnscache
    process needs admin, and that is the only proof DoH is actually carrying
    traffic rather than merely being configured. Everything else works
    unelevated.

    Compare against baseline-20260806.txt in this folder.
#>

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) { Write-Host "NOT ELEVATED - DoH session check will be skipped.`n" -ForegroundColor Yellow }

$fail = @()

Write-Host "==== DNS CLIENT SERVICE ====" -ForegroundColor Cyan
# This is what died on 2026-08-06. Dnscache runs inside svchost and has no
# binary of its own: ServiceDll IS the service. If it goes missing nothing
# resolves on ANY adapter, and swapping Wi-Fi for USB ethernet does not help.
$svc = Get-Service Dnscache -EA SilentlyContinue
"  service: $($svc.Status)/$($svc.StartType)"
if ($svc.Status -ne 'Running') { $fail += 'Dnscache not running' }
$k = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -EA SilentlyContinue
foreach ($vn in 'ServiceDll','extension','ServiceDllUnloadOnStop') {
  $ok = $k -and ($k.GetValueNames() -contains $vn)
  "  {0,-24} {1}" -f $vn, $(if ($ok) { "present ($($k.GetValueKind($vn)))" } else { 'MISSING' })
  if (-not $ok) { $fail += "Dnscache\Parameters missing $vn" }
}

Write-Host "`n==== ENCRYPTED DNS ====" -ForegroundColor Cyan
$guid = (Get-NetAdapter -InterfaceAlias 'Wi-Fi' -EA SilentlyContinue).InterfaceGuid
$ns   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -EA SilentlyContinue).NameServer
$srv  = (Get-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 -EA SilentlyContinue).ServerAddresses
"  Wi-Fi servers      : $($srv -join ', ')"
"  static NameServer  : '$ns'   (empty = reverted to DHCP)"
"  EnableAutoDoh      : $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -EA SilentlyContinue).EnableAutoDoh)  (want 2)"
if ([string]::IsNullOrWhiteSpace($ns)) { $fail += 'DNS reverted to DHCP - run Set-EncryptedDns.ps1 -Apply' }
# A server with AutoUpgrade=False is queried in CLEARTEXT even with DoH "on".
# 1.0.0.1 and 8.8.4.4 are False by default - that is why they are not used.
Get-DnsClientDohServerAddress -EA SilentlyContinue |
  Where-Object { $_.ServerAddress -in $srv } |
  ForEach-Object {
    "  {0,-16} AutoUpgrade={1} UdpFallback={2}" -f $_.ServerAddress, $_.AutoUpgrade, $_.AllowFallbackToUdp
    if (-not $_.AutoUpgrade) { $script:fail += "$($_.ServerAddress) would be queried in cleartext" }
  }

if ($elevated) {
  # Force an uncached lookup so Dnscache has a reason to open its TLS session,
  # then look for it. Config says "should"; an established socket says "is".
  Resolve-DnsName "$((New-Guid).Guid).example.com" -EA SilentlyContinue | Out-Null
  Start-Sleep -Seconds 2
  $svcPid = (Get-CimInstance Win32_Service -Filter "Name='Dnscache'" -EA SilentlyContinue).ProcessId
  $sess = Get-NetTCPConnection -State Established -RemotePort 443 -EA SilentlyContinue |
            Where-Object { $_.OwningProcess -eq $svcPid -and $_.RemoteAddress -in $srv }
  if ($sess) { "  LIVE DoH -> $((($sess.RemoteAddress) | Select-Object -Unique) -join ', ')" }
  else { "  LIVE DoH -> none seen (normal if nothing has queried recently)" }
}

Write-Host "`n==== INBOUND FIREWALL ====" -ForegroundColor Cyan
# AllowInboundRules=False is the real switch. DefaultInboundAction=Block alone
# still lets 89 allow rules through as exceptions.
foreach ($p in 'Domain','Private','Public') {
  $pe = Get-NetFirewallProfile -Profile $p -PolicyStore PersistentStore -EA SilentlyContinue
  $ac = Get-NetFirewallProfile -Profile $p -PolicyStore ActiveStore -EA SilentlyContinue
  "  {0,-9} inbound={1} allowRules={2}   (persistent store: {3}/{4})" -f $p,$ac.DefaultInboundAction,$ac.AllowInboundRules,$pe.DefaultInboundAction,$pe.AllowInboundRules
  if ($ac.AllowInboundRules -ne 'False' -or $ac.DefaultInboundAction -ne 'Block') { $fail += "$p profile not fully blocking inbound" }
  if ($pe.AllowInboundRules -ne $ac.AllowInboundRules) { $fail += "$p persistent/active mismatch - will not survive reboot" }
}
"  live profile: " + (Get-NetConnectionProfile -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty NetworkCategory)
# -DisplayName and -Direction are different parameter sets and cannot be
# combined; filter direction afterwards or the query silently returns nothing.
$cast = @(Get-NetFirewallRule -DisplayName 'Wireless Display*','WFD *','Proximity sharing*','Cast to Device*' -EA SilentlyContinue |
            Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' })
"  cast/WFD/proximity inbound rules enabled: $($cast.Count)  (want 0)"
if ($cast.Count) { $fail += "$($cast.Count) cast/WFD rules re-enabled" }

Write-Host "`n==== OTHER HARDENING ====" -ForegroundColor Cyan
foreach ($s in 'LanmanServer','RemoteRegistry','SSDPSRV','FDResPub','upnphost','TermService') {
  $x = Get-Service $s -EA SilentlyContinue
  "  {0,-16} {1}" -f $s, $(if ($x) { "$($x.Status)/$($x.StartType)" } else { 'not present' })
}
Get-LocalUser | Where-Object { $_.Name -in 'Administrator','Guest','Kusum Singh' } |
  ForEach-Object { "  account {0,-16} Enabled={1}" -f $_.Name, $_.Enabled }

Write-Host "`n==== SAFETY NETS ====" -ForegroundColor Cyan
$t = Get-ScheduledTask -TaskName 'SecureVault-*' -EA SilentlyContinue
if ($t) { $t | ForEach-Object { Write-Host "  ARMED: $($_.TaskName) - will auto-revert at $((Get-ScheduledTaskInfo $_).NextRunTime). Run -Disarm." -ForegroundColor Yellow } }
else { "  no dead-man tasks armed" }
if (Test-Path 'C:\Users\User\BitLocker-Recovery-C.txt') {
  Write-Host "  BitLocker recovery key STILL on the encrypted drive - move it offline." -ForegroundColor Yellow
}

Write-Host "`n==== CONNECTIVITY ====" -ForegroundColor Cyan
$ok = 0; foreach ($n in 'microsoft.com','cloudflare.com','example.com') { if (Resolve-DnsName $n -Type A -EA SilentlyContinue -QuickTimeout) { $ok++ } }
"  DNS resolves : $ok/3"
"  tcp/443 out  : " + (Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
if ($ok -lt 2) { $fail += 'DNS resolution failing' }

Write-Host "`n==== VERDICT ====" -ForegroundColor Cyan
if ($fail.Count -eq 0) { Write-Host "  ALL GOOD - everything applied and persistent." -ForegroundColor Green }
else {
  Write-Host "  $($fail.Count) problem(s):" -ForegroundColor Red
  $fail | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
  Write-Host @"

  Recovery, in order of escalation:
    .\Set-EncryptedDns.ps1 -Apply      # DNS reverted to DHCP
    .\Set-EncryptedDns.ps1 -Revert     # DNS broken / captive portal won't load
    .\Block-AllInbound.ps1 -Revert     # something needs inbound
    .\Revert-FixGaps.ps1 -RepairDns    # NOTHING resolves at all (service-level)
"@ -ForegroundColor Yellow
}
