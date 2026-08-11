<#
    Harden-Laptop.ps1  -  outbound-only work-laptop hardening
    RUN IN AN ELEVATED (Administrator) PowerShell.

    Philosophy: allow all OUTGOING, block ALL unsolicited INCOMING, and remove
    the classic Windows LAN/remote attack vectors. Every change is reversible;
    a companion revert block is at the bottom (commented).

    Review each section before running. You can paste section-by-section.
    Read the CAVEATS near the top first.
#>

[CmdletBinding()]
param(
  [switch]$CreateRestorePoint
)

$ErrorActionPreference = 'Continue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = "C:\SecureVault\Backups\Harden-Laptop-$ts"
New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null

if ($CreateRestorePoint) {
  try {
    Checkpoint-Computer -Description "Pre-Harden-Laptop $ts" -RestorePointType MODIFY_SETTINGS
    Write-Host "Restore point created: Pre-Harden-Laptop $ts" -ForegroundColor Green
  } catch {
    Write-Warning "Could not create restore point: $($_.Exception.Message)"
  }
}

try {
  netsh advfirewall export "$backupRoot\firewall.wfw" | Out-Null
} catch {
  Write-Warning "Firewall export failed: $($_.Exception.Message)"
}

foreach ($rk in @(
  'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient',
  'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters',
  'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
)) {
  $name = ($rk -replace '[\\:]', '_') + '.reg'
  reg.exe export $rk "$backupRoot\$name" /y | Out-Null
}

Write-Host "Backup folder: $backupRoot" -ForegroundColor Yellow

# ============================ CAVEATS (read me) ============================
# Blocking all inbound + disabling these services will STOP:
#   - HP "Scan to PC" (printer pushing scans to this laptop needs inbound)
#   - hosting file/printer shares FROM this laptop (accessing OTHERS' shares
#     still works - that's outbound)
#   - Remote Desktop / SSH / WinRM INTO this laptop (already off anyway)
#   - this laptop appearing in "Network" / casting / device discovery
# Still works: web, email, VPN, outbound SSH/RDP, cloud sync, accessing shares.
# RunAsPPL (LSASS protection) can block tools that inject into LSASS (rare).
# ASR + Controlled Folder Access start in AUDIT mode so nothing breaks; flip to
# Block later once you've confirmed your apps are clean in the logs.
# ==========================================================================

Write-Host "`n==== SECTION 1: FIREWALL - allow outbound, block ALL inbound ====" -ForegroundColor Cyan
# explicit intent on every profile
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -AllowInboundRules True -NotifyOnListen False
# Close the inbound rule GROUPS that open listeners (they no longer match).
$killGroups = @(
  'File and Printer Sharing','Network Discovery','mDNS','Cast to Device',
  'Remote Desktop','Remote Assistance','Windows Remote Management',
  'Remote Event Log Management','Remote Service Management',
  'Remote Scheduled Tasks Management','Remote Volume Management',
  'Windows Media Player Network Sharing Service','AllJoyn Router',
  'Delivery Optimization','Wi-Fi Direct Network Discovery'
)
foreach ($g in $killGroups) {
  # NOTE: do NOT filter by -Group with a wildcard. '@FirewallAPI.dll,-*' matches
  # ~200 built-in rules INCLUDING Core Networking DHCP-In / Router Advertisement /
  # Neighbor Discovery. Disabling those stops DHCP and IPv6 autoconfig, which
  # kills Wi-Fi (connected but no address). Match on DisplayGroup only.
  Get-NetFirewallRule -Direction Inbound -EA SilentlyContinue |
    Where-Object DisplayGroup -eq $g | Disable-NetFirewallRule -EA SilentlyContinue
}
# Keep Core Networking inbound (DHCP/DNS replies, IPv6 ND) so the net still works.
Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize

# Quick outbound connectivity probe right after firewall changes.
$netProbe = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -WarningAction SilentlyContinue
if (-not $netProbe.TcpTestSucceeded) {
  Write-Warning "Outbound probe failed after firewall changes. Roll back immediately if connectivity is impacted: netsh advfirewall import $backupRoot\\firewall.wfw"
}

Write-Host "`n==== SECTION 2: kill LAN name-poisoning vectors (LLMNR / NBT-NS / mDNS) ====" -ForegroundColor Cyan
# LLMNR off (Responder's #1 vector)
# Create keys only when absent: New-Item -Force on an existing key deletes and
# recreates it EMPTY, silently discarding whatever values were already there.
$dnsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (-not (Test-Path $dnsPol)) { New-Item $dnsPol -Force | Out-Null }
Set-ItemProperty $dnsPol EnableMulticast 0 -Type DWord
# NetBIOS over TCP/IP off on every adapter (NBT-NS poisoning)
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
  ForEach-Object { Set-ItemProperty $_.PSPath 'NetbiosOptions' 2 -Type DWord -EA SilentlyContinue }
# Global P-node so no NetBIOS broadcast even on new adapters
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' NodeType 2 -Type DWord
"LLMNR + NBT-NS disabled"

$dnsProbe = Resolve-DnsName microsoft.com -EA SilentlyContinue | Select-Object -First 1 Name,IPAddress
if ($dnsProbe) {
  $dnsProbe
} else {
  Write-Warning "DNS probe failed after name-resolution hardening. Use System Restore if browsing/DNS is broken."
}

Write-Host "`n==== SECTION 3: disable SMBv1, require SMB signing, harden SMB ====" -ForegroundColor Cyan
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -EA SilentlyContinue | Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -EA SilentlyContinue
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -EA SilentlyContinue
Set-SmbClientConfiguration  -RequireSecuritySignature $true -Force -EA SilentlyContinue
Set-SmbClientConfiguration  -EnableInsecureGuestLogons $false -Force -EA SilentlyContinue
"SMBv1 removed; SMB signing required; insecure guest logons off"

Write-Host "`n==== SECTION 4: turn off inbound-exposing services ====" -ForegroundColor Cyan
# server=host shares (inbound). Client access to others' shares is a different svc.
$svc = @{
  LanmanServer   = 'Disabled'   # stop hosting SMB shares (inbound)
  FDResPub       = 'Disabled'   # stop publishing this PC for discovery
  SSDPSRV        = 'Disabled'   # UPnP discovery
  upnphost       = 'Disabled'
  RemoteRegistry = 'Disabled'
  WinRM          = 'Disabled'
  RemoteAccess   = 'Disabled'
}
foreach ($n in $svc.Keys) {
  Set-Service $n -StartupType $svc[$n] -EA SilentlyContinue
  Stop-Service $n -Force -EA SilentlyContinue
}
Get-Service $svc.Keys -EA SilentlyContinue | Select-Object Name,Status,StartType | Format-Table -AutoSize

Write-Host "`n==== SECTION 5: Defender ASR + SmartScreen + ransomware guard ====" -ForegroundColor Cyan
# Widely-recommended ASR rule GUIDs, started in AUDIT (2) so nothing breaks yet.
$asr = @(
 '56a863a9-875e-4185-98a7-b882c64b5ce5','7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','01443614-cd74-433a-b99e-2ecdc07bfc25',
 '5beb7efe-fd9a-4556-801d-275e5ffc04cc','d3e037e1-3eb8-44c8-a917-57927947596d',
 '3b576869-a4ec-4529-8536-b80a7769e899','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
 '26190899-1602-49e8-8b27-eb1d0a1ce869','e6db77e5-3df2-4cf1-b95a-636979351e5b',
 'd1e49aac-8f56-4280-b9ba-993a6d77406c','b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
)
foreach ($id in $asr) { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode -EA SilentlyContinue }
Set-MpPreference -PUAProtection Enabled -EA SilentlyContinue
Set-MpPreference -EnableControlledFolderAccess AuditMode -EA SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 1 -EA SilentlyContinue
# SmartScreen for apps + Edge
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen 1 -Type DWord -Force -EA SilentlyContinue
"ASR (audit), PUA block, Controlled Folder Access (audit), SmartScreen on"

Write-Host "`n==== SECTION 6: credential + LSASS protection ====" -ForegroundColor Cyan
# RunAsPPL: protect LSASS from credential dumping (Mimikatz)
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL 1 -Type DWord -EA SilentlyContinue
# never cache WDigest plaintext creds
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
if (-not (Test-Path $wdigest)) { New-Item $wdigest -Force | Out-Null }   # preserves existing Negotiate value
Set-ItemProperty $wdigest UseLogonCredential 0 -Type DWord
"LSASS PPL + WDigest hardening set (LSASS PPL needs a reboot)"

Write-Host "`n==== SECTION 7: misc surface reduction ====" -ForegroundColor Cyan
# Disable AutoRun/AutoPlay for all drives (USB-borne malware)
$expPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
if (-not (Test-Path $expPol)) { New-Item $expPol -Force | Out-Null }   # preserves other Explorer policies
Set-ItemProperty $expPol NoDriveTypeAutoRun 255 -Type DWord
# UAC: prompt on the secure desktop for any elevation
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ConsentPromptBehaviorAdmin 2 -Type DWord -EA SilentlyContinue
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' PromptOnSecureDesktop 1 -Type DWord -EA SilentlyContinue
# Remove legacy PowerShell v2 (downgrade-attack surface).
# Windows 11 24H2+ (build 26100+) dropped the feature entirely, so the cmdlet
# throws "Feature name ... is unknown" - and -EA SilentlyContinue does NOT
# suppress it, because DISM surfaces it as a COMException. Check first.
$v2Key = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
if (Test-Path $v2Key) {
  foreach ($f in 'MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root') {
    try   { Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -ErrorAction Stop | Out-Null }
    catch { "  PowerShell v2 feature '$f' not present on this build - nothing to do" }
  }
  "PowerShell v2 disabled (reboot to complete)"
} else {
  "PowerShell v2 engine not installed on this build - nothing to remove"
}
"AutoRun off, UAC hardened"

Write-Host "`n==== SECTION 8: disk encryption status (theft protection) ====" -ForegroundColor Cyan
manage-bde -status C: | Select-String 'Conversion Status|Protection Status|Encryption Method'
Write-Host "If Protection Status is OFF, enable BitLocker: manage-bde -on C: -RecoveryPassword (save the recovery key OFFLINE)." -ForegroundColor Yellow

Write-Host "`nDONE. Reboot to fully apply LSASS PPL, SMBv1 removal, and PowerShell v2 removal." -ForegroundColor Green
Write-Host "If post-reboot behavior is bad, use System Restore first. Backup artifacts are in: $backupRoot" -ForegroundColor Yellow

<#  ===================== REVERT (paste to undo) =====================
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction NotConfigured
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 1
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL 0
foreach($n in 'LanmanServer','FDResPub','SSDPSRV'){ Set-Service $n -StartupType Automatic; Start-Service $n }
Set-MpPreference -EnableControlledFolderAccess Disabled
# (re-enable File and Printer Sharing / Network Discovery inbound rule groups in wf.msc as needed)
================================================================== #>
