<#
    Fix-Gaps.ps1  -  close the remaining security gaps
    RUN IN AN ELEVATED (Administrator) PowerShell.
    Review each section; you can run them one at a time.
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
$backupRoot = "C:\SecureVault\Backups\Fix-Gaps-$ts"
New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null

if ($CreateRestorePoint) {
  try {
    Checkpoint-Computer -Description "Pre-Fix-Gaps $ts" -RestorePointType MODIFY_SETTINGS
    Write-Host "Restore point created: Pre-Fix-Gaps $ts" -ForegroundColor Green
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
  'HKLM\SOFTWARE\Policies\Microsoft\FVE',
  'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters',
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
)) {
  $name = ($rk -replace '[\\:]', '_') + '.reg'
  reg.exe export $rk "$backupRoot\$name" /y | Out-Null
}

Write-Host "Backup folder: $backupRoot" -ForegroundColor Yellow

Write-Host "`n==== SECTION A: ACCOUNTS ====" -ForegroundColor Cyan
"Current accounts:"
Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,LastLogon | Format-Table -AutoSize

# 'Kusum Singh' - enabled, no password, last logon 2024. Disable it (reversible).
try {
  Disable-LocalUser -Name 'Kusum Singh' -EA Stop
  "Disabled account: Kusum Singh"
} catch { "Kusum Singh: $($_.Exception.Message)" }
# To DELETE it entirely (IRREVERSIBLE - erases that profile's data), run manually:
#     Remove-LocalUser -Name 'Kusum Singh'

# Built-in Administrator should stay disabled (use your 'User' admin instead)
Disable-LocalUser -Name 'Administrator' -EA SilentlyContinue
"Built-in Administrator disabled (if it was enabled)"

# Disable the Guest account if present
Disable-LocalUser -Name 'Guest' -EA SilentlyContinue

# Require a real password on your daily account. Set a strong one now:
Write-Host "ACTION: set a strong password on 'User' (skip if you use a Microsoft account / Hello):" -ForegroundColor Yellow
Write-Host "        net user User *" -ForegroundColor Yellow
# enforce minimums for any local account
net accounts /minpwlen:14 /maxpwage:365 | Out-Null
"Password policy: min length 14 set"
"`nAfter:"
Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | Format-Table -AutoSize

Write-Host "`n==== SECTION B: BITLOCKER pre-boot PIN + recovery key backup ====" -ForegroundColor Cyan
# allow a startup PIN via policy
$fve='HKLM:\SOFTWARE\Policies\Microsoft\FVE'
if (-not (Test-Path $fve)) { New-Item $fve -Force | Out-Null }   # -Force on an existing key wipes its values
Set-ItemProperty $fve UseAdvancedStartup 1 -Type DWord
Set-ItemProperty $fve EnableBDEWithNoTPM 0 -Type DWord
Set-ItemProperty $fve UseTPMPIN 1 -Type DWord
Set-ItemProperty $fve UseTPM 2 -Type DWord
# ensure a recovery-password protector exists, then export it to save OFFLINE
if (-not (manage-bde -protectors -get C: | Select-String 'Numerical Password')) {
  manage-bde -protectors -add C: -RecoveryPassword | Out-Null
}
$rk = "C:\Users\User\BitLocker-Recovery-C.txt"  # local, NOT OneDrive-synced
manage-bde -protectors -get C: | Out-File $rk -Encoding utf8
Write-Host "Recovery key written to: $rk  --> MOVE IT TO OFFLINE STORAGE, then delete from Desktop." -ForegroundColor Yellow
Write-Host "ACTION: add the pre-boot PIN (you'll be prompted to choose it):" -ForegroundColor Yellow
Write-Host "        manage-bde -protectors -add C: -TPMAndPIN" -ForegroundColor Yellow

Write-Host "`n==== SECTION C: remove Java (legacy attack surface) ====" -ForegroundColor Cyan
$java = Get-ChildItem 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath } |
        Where-Object { $_.DisplayName -match '(?i)^Java (8|Auto|SE)' }
if ($java) {
  foreach ($j in $java) {
    "$($j.DisplayName)"
    if ($j.UninstallString -match '\{[0-9A-F\-]+\}') {
      Start-Process msiexec.exe -ArgumentList "/x $($Matches[0]) /qn /norestart" -Wait
    }
  }
  "Java uninstall attempted - re-run this section's Get to confirm it's gone."
} else { "No Java found (already removed)." }

Write-Host "`n==== SECTION D: encrypted DNS (DoH) ====" -ForegroundColor Cyan
$dnsParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'

# ---- guard 1: never lose the DNS Client service implementation ----------------
# Dnscache is 'svchost.exe -k NetworkService -p' - it has NO binary of its own.
# ServiceDll (REG_EXPAND_SZ -> dnsrslvr.dll) IS the service. If that value goes
# missing, svchost has nothing to load, DNS Client never starts, and NOTHING
# resolves on ANY adapter - swapping Wi-Fi for a USB LAN does not help, because
# the break is in the service, not the NIC. NCSI then can't resolve
# www.msftconnecttest.com either, so every network also shows "No Internet".
#
# 'New-Item -Force' on an EXISTING key DELETES AND RECREATES IT EMPTY, which is
# exactly how that value gets lost. Create the key only if genuinely absent.
$dnsCritical = @{
  ServiceDll             = @{ Kind = 'ExpandString'; Data = '%SystemRoot%\System32\dnsrslvr.dll' }
  extension              = @{ Kind = 'ExpandString'; Data = '%SystemRoot%\System32\dnsext.dll'  }
  ServiceDllUnloadOnStop = @{ Kind = 'DWord';        Data = 1                                    }
}
if (-not (Test-Path $dnsParams)) { New-Item $dnsParams -Force | Out-Null }

# ---- guard 2: DoH must degrade, not fail closed -------------------------------
# 'netsh dns add encryption' FAILS silently if the server already has an entry -
# and 1.1.1.1 / 8.8.8.8 ship in Windows' built-in well-known-resolver table, so
# 'add' is a no-op on a stock machine. Use 'set' when the entry exists.
#
# udpfallback=yes is deliberate. With autoupgrade=yes + udpfallback=no, any
# network that blocks or intercepts 443 to the resolver kills DNS outright with
# no plain-DNS fallback - which is what a hotel/airport captive portal does
# before you've logged in. You cannot even reach the login page. This laptop has
# Hilton Honors / Comfort Inn / Cambria_GUEST profiles saved, so that is a real
# scenario, not a hypothetical. The tradeoff: an attacker who can block 443 can
# force a downgrade to plaintext DNS. For a travelling laptop that is the right
# trade. Set $StrictDoH = $true only if this machine never leaves a known network.
$StrictDoH = $false
$udpFallback = if ($StrictDoH) { 'no' } else { 'yes' }

$dohServers = @(
  @{ Server = '1.1.1.1'; Template = 'https://cloudflare-dns.com/dns-query' }
  @{ Server = '8.8.8.8'; Template = 'https://dns.google/dns-query'         }
)
$existing = (netsh dns show encryption) -join "`n"
foreach ($d in $dohServers) {
  $verb = if ($existing -match [regex]::Escape($d.Server)) { 'set' } else { 'add' }
  # No '2>&1' here: in Windows PowerShell 5.1 redirecting a native command's
  # stderr wraps each line in a NativeCommandError record and flips $? to false
  # even on a clean exit. $LASTEXITCODE is the reliable signal.
  $out = netsh dns $verb encryption server=$($d.Server) dohtemplate=$($d.Template) `
                autoupgrade=yes udpfallback=$udpFallback
  if ($LASTEXITCODE -ne 0) { Write-Warning "DoH $verb failed for $($d.Server): $out" }
  else { "  DoH $verb $($d.Server)  (udpfallback=$udpFallback)" }
}

# 2 = allow automatic DoH upgrade. (The old value here was 0, which DISABLES it.)
Set-ItemProperty $dnsParams EnableAutoDoh 2 -Type DWord

# ---- guard 3: verify we did not just break DNS, and self-heal if we did -------
$k = Get-Item $dnsParams
$names = $k.GetValueNames()
foreach ($vn in $dnsCritical.Keys) {
  if ($names -notcontains $vn) {
    Write-Warning "Dnscache\Parameters is missing '$vn' - restoring it (DNS would be dead otherwise)."
    New-ItemProperty $dnsParams -Name $vn -PropertyType $dnsCritical[$vn].Kind `
                     -Value $dnsCritical[$vn].Data -Force | Out-Null
  }
}
"DoH configured for 1.1.1.1 and 8.8.8.8; DNS Client key verified intact"

# Sanity check - if this is not Running, DNS is broken:
Get-Service Dnscache | Select-Object Name,Status,StartType | Format-Table -AutoSize
$dnsProbe = Resolve-DnsName microsoft.com -EA SilentlyContinue | Select-Object -First 1 Name,IPAddress
if ($dnsProbe) {
  $dnsProbe
} else {
  Write-Warning @"
DNS probe FAILED. Recover with these three lines in an elevated prompt, then reboot:
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%SystemRoot%\System32\dnsrslvr.dll" /f
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v extension /t REG_EXPAND_SZ /d "%SystemRoot%\System32\dnsext.dll" /f
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v ServiceDllUnloadOnStop /t REG_DWORD /d 1 /f
To undo DoH only:  netsh dns delete encryption server=1.1.1.1 ; netsh dns delete encryption server=8.8.8.8
Registry backup for this run: $backupRoot
"@
}

Write-Host "`n==== SECTION E: verify Secure Boot ====" -ForegroundColor Cyan
try { "Secure Boot enabled: " + (Confirm-SecureBootUEFI) } catch { "could not read: $($_.Exception.Message)" }

Write-Host "`nDONE. Set the 'User' password and add the BitLocker PIN (the two ACTION lines), then reboot." -ForegroundColor Green
Write-Host "If anything breaks after reboot, use System Restore first. Backup artifacts are in: $backupRoot" -ForegroundColor Yellow
