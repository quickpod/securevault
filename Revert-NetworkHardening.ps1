<#
    Revert-NetworkHardening.ps1

    Selectively undoes the NETWORK-affecting parts of Harden-Laptop.ps1.
    Everything else that script did (SMB signing, ASR, UAC, AutoRun, WDigest,
    BitLocker checks) is left alone - none of it affects connectivity.

    RUN IN AN ELEVATED (Administrator) PowerShell.

    Nothing runs unless you pass a switch. Pick what you need:

      -LocalNameResolution   fixes short hostnames / .local not resolving
      -DeviceDiscovery       fixes casting, wireless display, HP printer discovery
      -NetworkLocation       restores NlaSvc to Automatic (network profile detection)
      -LsassPPL              undoes RunAsPPL (only if 802.1X / enterprise Wi-Fi broke)
      -All                   all of the above

    -Scope controls which firewall profiles get rules re-enabled.
    Default is Private only, which is what you want on a home/office LAN.
    Use 'Private','Domain' or add 'Public' only if you know you need it.
#>

[CmdletBinding()]
param(
  [switch]$LocalNameResolution,
  [switch]$DeviceDiscovery,
  [switch]$NetworkLocation,
  [switch]$LsassPPL,
  [switch]$All,
  [ValidateSet('Domain','Private','Public')]
  [string[]]$Scope = @('Private')
)

$ErrorActionPreference = 'Continue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

if ($All) {
  $LocalNameResolution = $DeviceDiscovery = $NetworkLocation = $LsassPPL = $true
}

if (-not ($LocalNameResolution -or $DeviceDiscovery -or $NetworkLocation -or $LsassPPL)) {
  Write-Host "No switch given - nothing to do. See the header for options." -ForegroundColor Yellow
  Write-Host "Most likely fix for your symptoms:" -ForegroundColor Yellow
  Write-Host "    .\Revert-NetworkHardening.ps1 -LocalNameResolution -DeviceDiscovery" -ForegroundColor Yellow
  return
}

# Re-enable an inbound rule group, but only on the requested profiles.
# A rule's Profile can be 'Any' or a comma list; re-enabling an 'Any' rule
# opens it everywhere, so those are reported rather than silently enabled.
function Enable-InboundGroup {
  param([string]$Group, [string[]]$Profiles)

  $rules = Get-NetFirewallRule -Direction Inbound -EA SilentlyContinue |
             Where-Object { $_.DisplayGroup -eq $Group -and $_.Enabled -eq 'False' }
  if (-not $rules) { "  $Group : nothing disabled"; return }

  $n = 0
  foreach ($r in $rules) {
    $rp = @($r.Profile -split ',\s*')
    if ($rp -contains 'Any' -or ($rp | Where-Object { $Profiles -contains $_ })) {
      Enable-NetFirewallRule -Name $r.Name -EA SilentlyContinue
      $n++
    }
  }
  "  $Group : re-enabled $n of $($rules.Count) rule(s) for $($Profiles -join ',')"
}

if ($LocalNameResolution) {
  Write-Host "`n==== LOCAL NAME RESOLUTION ====" -ForegroundColor Cyan

  # LLMNR back on. Deleting the value is cleaner than setting 1 - it returns the
  # machine to "not configured" rather than explicitly-enabled-by-policy.
  $dnsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
  if (Test-Path $dnsPol) {
    Remove-ItemProperty $dnsPol -Name EnableMulticast -EA SilentlyContinue
    "  LLMNR: EnableMulticast policy removed (back to Windows default = on)"
  }

  # NodeType 2 = P-node: NetBIOS names resolve via WINS only. With no WINS server
  # configured that means single-label names never resolve at all. Removing the
  # value restores H-node (broadcast + WINS), the Windows default.
  Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
    -Name NodeType -EA SilentlyContinue
  "  NetBIOS: global NodeType removed (back to default H-node)"

  # Per-adapter NetbiosOptions: 0 = use DHCP server's setting (the default),
  # 1 = enabled, 2 = disabled. Harden-Laptop set every interface to 2.
  Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -EA SilentlyContinue |
    ForEach-Object { Set-ItemProperty $_.PSPath 'NetbiosOptions' 0 -Type DWord -EA SilentlyContinue }
  "  NetBIOS: all interfaces set back to 0 (defer to DHCP)"

  # mDNS - required for .local names and most modern printer/IoT discovery.
  Enable-InboundGroup -Group 'mDNS' -Profiles $Scope

  Write-Host "  Reboot (or disable/re-enable the adapter) for NetBT changes to take effect." -ForegroundColor Yellow
}

if ($DeviceDiscovery) {
  Write-Host "`n==== DEVICE DISCOVERY (casting, wireless display, printers) ====" -ForegroundColor Cyan

  foreach ($g in 'Network Discovery','Wi-Fi Direct Network Discovery','Cast to Device') {
    Enable-InboundGroup -Group $g -Profiles $Scope
  }

  # FDResPub publishes this PC for discovery; SSDPSRV/upnphost are UPnP, which is
  # what casting and most network printers actually use to find each other.
  foreach ($n in 'FDResPub','SSDPSRV','upnphost') {
    Set-Service $n -StartupType Manual -EA SilentlyContinue
    Start-Service $n -EA SilentlyContinue
  }
  Get-Service FDResPub,SSDPSRV,upnphost -EA SilentlyContinue |
    Select-Object Name,Status,StartType | Format-Table -AutoSize

  Write-Host "  NOTE: 'File and Printer Sharing' inbound is still disabled. That only" -ForegroundColor Yellow
  Write-Host "        affects OTHERS reaching shares ON this laptop (incl. HP Scan-to-PC)." -ForegroundColor Yellow
  Write-Host "        You reaching other machines' shares is outbound and already works." -ForegroundColor Yellow
}

if ($NetworkLocation) {
  Write-Host "`n==== NETWORK LOCATION AWARENESS ====" -ForegroundColor Cyan
  # NlaSvc classifies each network as Domain/Private/Public. If it is not running,
  # Windows can mis-apply the firewall profile and show "No internet access".
  Set-Service NlaSvc -StartupType Automatic -EA SilentlyContinue
  Start-Service NlaSvc -EA SilentlyContinue
  Get-Service NlaSvc,netprofm,Netman -EA SilentlyContinue |
    Select-Object Name,Status,StartType | Format-Table -AutoSize
}

if ($LsassPPL) {
  Write-Host "`n==== LSASS PPL ====" -ForegroundColor Cyan
  # Only worth undoing if WPA2-Enterprise / 802.1X or a VPN supplicant broke -
  # those hook LSASS and PPL blocks them. This measurably weakens credential
  # protection, so leave it alone unless that is actually your symptom.
  $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  Set-ItemProperty $lsa RunAsPPL 0 -Type DWord -EA SilentlyContinue
  Remove-ItemProperty $lsa -Name RunAsPPLBoot -EA SilentlyContinue
  "  RunAsPPL disabled - REBOOT REQUIRED. Re-enable it once the real cause is found."
}

Write-Host "`n==== VERIFY ====" -ForegroundColor Cyan
$probe = Resolve-DnsName microsoft.com -EA SilentlyContinue | Select-Object -First 1
if ($probe) { "  Public DNS OK -> $($probe.IPAddress)$($probe.NameHost)" }
else        { Write-Warning "  Public DNS still failing - that is a different problem." }

Write-Host "`nDone. Reboot, then test the LAN name that was failing." -ForegroundColor Green
