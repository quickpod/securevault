<#
    Revert-FixGaps.ps1  -  undo what Fix-Gaps.ps1 changed

    RUN IN AN ELEVATED (Administrator) PowerShell.

    DESIGNED TO WORK WITH NO NETWORK. The failure mode this exists for is
    "DNS Client is dead, nothing resolves, I cannot download a fix" - so this
    script never downloads anything, and -RepairDns does not need the backup
    folder. Keep a copy on a USB stick.

    Run with no switches for a read-only health check that tells you which
    switch you actually need.

      -RepairDns     EMERGENCY. Restore the DNS Client service key and undo all
                     DoH changes. No backup folder needed. Start here.
      -BitLocker     Remove the FVE pre-boot PIN policy (Section B).
      -Accounts      Undo the password policy / re-enable 'Kusum Singh' (Section A).
      -All           All of the above.

      -BackupPath    A C:\SecureVault\Backups\Fix-Gaps-* folder to restore .reg
                     files from. Auto-detects the newest if omitted. Optional -
                     -RepairDns works without it.

    NOT REVERSIBLE: Section C uninstalled Java. This script cannot bring it back;
    reinstall from the vendor if you need it.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [switch]$RepairDns,
  [switch]$BitLocker,
  [switch]$Accounts,
  [switch]$All,
  [string]$BackupPath
)

$ErrorActionPreference = 'Continue'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

if ($All) { $RepairDns = $BitLocker = $Accounts = $true }

$dnsParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
$fve       = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'

# The three values that ARE the DNS Client service. Dnscache runs inside
# svchost (-k NetworkService -p) and has no binary of its own, so if ServiceDll
# goes missing the service cannot start and NOTHING resolves on ANY adapter -
# swapping Wi-Fi for a USB LAN does not help. Types matter: REG_EXPAND_SZ, not
# REG_SZ, or %SystemRoot% is never expanded and the service still fails.
$dnsCritical = [ordered]@{
  ServiceDll             = @{ Kind = 'ExpandString'; Data = '%SystemRoot%\System32\dnsrslvr.dll' }
  extension              = @{ Kind = 'ExpandString'; Data = '%SystemRoot%\System32\dnsext.dll'  }
  ServiceDllUnloadOnStop = @{ Kind = 'DWord';        Data = 1                                    }
}

# Servers Fix-Gaps Section D touched, and the stock Windows settings for them.
# These ship in Windows' built-in well-known-resolver table, so the correct
# revert is to SET them back to the defaults, not DELETE them (deleting would
# leave the machine less stock than it started).
$dohServers = @(
  @{ Server = '1.1.1.1'; Template = 'https://cloudflare-dns.com/dns-query' }
  @{ Server = '8.8.8.8'; Template = 'https://dns.google/dns-query'         }
)

function Get-DnsHealth {
  $h = [ordered]@{}
  $svc = Get-Service Dnscache -EA SilentlyContinue
  $h.ServiceStatus = if ($svc) { "$($svc.Status)/$($svc.StartType)" } else { 'MISSING' }

  $missing = @()
  if (Test-Path $dnsParams) {
    $k = Get-Item $dnsParams
    $names = $k.GetValueNames()
    foreach ($vn in $dnsCritical.Keys) {
      if ($names -notcontains $vn) { $missing += $vn }
      elseif ($k.GetValueKind($vn) -ne $dnsCritical[$vn].Kind) { $missing += "$vn (wrong type)" }
    }
    $h.EnableAutoDoh = if ($names -contains 'EnableAutoDoh') { $k.GetValue('EnableAutoDoh') } else { '<not set>' }
  } else {
    $missing += 'ENTIRE KEY'
    $h.EnableAutoDoh = '<key absent>'
  }
  $h.MissingValues = if ($missing) { $missing -join ', ' } else { 'none' }

  $enc = (netsh dns show encryption) -join "`n"
  $forced = @()
  foreach ($d in $dohServers) {
    # Grab the block for this server and see whether auto-upgrade got turned on.
    if ($enc -match "(?s)Encryption settings for $([regex]::Escape($d.Server))\s.*?Auto-upgrade\s*:\s*(\w+)") {
      if ($Matches[1] -eq 'yes') { $forced += $d.Server }
    }
  }
  $h.ForcedDoH = if ($forced) { $forced -join ', ' } else { 'none' }
  $h.Resolves  = [bool](Resolve-DnsName microsoft.com -EA SilentlyContinue)
  [pscustomobject]$h
}

# ---------------------------------------------------------------- health check
Write-Host "`n==== DNS HEALTH ====" -ForegroundColor Cyan
$before = Get-DnsHealth
$before | Format-List

if (-not ($RepairDns -or $BitLocker -or $Accounts)) {
  Write-Host "Read-only check. Nothing changed." -ForegroundColor Yellow
  if ($before.MissingValues -ne 'none' -or -not $before.Resolves -or $before.ForcedDoH -ne 'none') {
    Write-Host "`nDNS looks broken. Run:" -ForegroundColor Red
    Write-Host "    .\Revert-FixGaps.ps1 -RepairDns" -ForegroundColor Red
  } else {
    Write-Host "`nDNS looks healthy - no revert needed. Use -BitLocker / -Accounts for those sections." -ForegroundColor Green
  }
  return
}

# ------------------------------------------------------- locate backup (option)
if (-not $BackupPath) {
  $BackupPath = Get-ChildItem 'C:\SecureVault\Backups' -Directory -EA SilentlyContinue |
                  Where-Object Name -like 'Fix-Gaps-*' |
                  Sort-Object LastWriteTime -Descending |
                  Select-Object -First 1 -ExpandProperty FullName
}
if ($BackupPath -and (Test-Path $BackupPath)) {
  Write-Host "`nUsing backup: $BackupPath" -ForegroundColor Yellow
} else {
  $BackupPath = $null
  Write-Host "`nNo Fix-Gaps backup folder found - using built-in known-good values." -ForegroundColor Yellow
}

# ================================================================ SECTION D
if ($RepairDns) {
  Write-Host "`n==== REVERT SECTION D: DNS / DoH ====" -ForegroundColor Cyan

  if ($PSCmdlet.ShouldProcess($dnsParams, 'Restore DNS Client service values')) {
    if (-not (Test-Path $dnsParams)) {
      # -Force is safe here ONLY because we just proved the key is absent.
      New-Item $dnsParams -Force | Out-Null
      "  Recreated missing Dnscache\Parameters key"
    }

    # Prefer the exported .reg if we have one - it carries the machine's real
    # original values. reg import MERGES, so it restores what was deleted but
    # will not remove EnableAutoDoh; that is handled explicitly below.
    $reg = if ($BackupPath) {
      Join-Path $BackupPath 'HKLM_SYSTEM_CurrentControlSet_Services_Dnscache_Parameters.reg'
    }
    if ($reg -and (Test-Path $reg)) {
      reg.exe import $reg | Out-Null
      if ($LASTEXITCODE -eq 0) { "  Imported $([IO.Path]::GetFileName($reg))" }
      else { Write-Warning "  reg import failed (exit $LASTEXITCODE) - falling back to built-in values" }
    }

    # Belt and braces: whether or not the import ran, guarantee the three
    # critical values exist with the correct types.
    $k = Get-Item $dnsParams
    $names = $k.GetValueNames()
    foreach ($vn in $dnsCritical.Keys) {
      $needs = ($names -notcontains $vn) -or ($k.GetValueKind($vn) -ne $dnsCritical[$vn].Kind)
      if ($needs) {
        New-ItemProperty $dnsParams -Name $vn -PropertyType $dnsCritical[$vn].Kind `
                         -Value $dnsCritical[$vn].Data -Force | Out-Null
        "  Restored $vn ($($dnsCritical[$vn].Kind))"
      }
    }

    # Undo the auto-DoH opt-in. Removing beats setting 0 - it returns the machine
    # to "not configured" rather than explicitly-disabled.
    Remove-ItemProperty $dnsParams -Name EnableAutoDoh -EA SilentlyContinue
    "  EnableAutoDoh removed (back to Windows default)"
  }

  # Put the two resolvers back to stock: no forced upgrade, no UDP fallback.
  foreach ($d in $dohServers) {
    if ($PSCmdlet.ShouldProcess($d.Server, 'Reset DoH settings to Windows default')) {
      netsh dns set encryption server=$($d.Server) dohtemplate=$($d.Template) `
            autoupgrade=no udpfallback=no | Out-Null
      if ($LASTEXITCODE -eq 0) { "  $($d.Server): auto-upgrade off (stock)" }
      else { Write-Warning "  Could not reset DoH for $($d.Server) (exit $LASTEXITCODE)" }
    }
  }

  # Per-adapter DoH overrides would survive everything above and keep forcing
  # encryption on one NIC. Fix-Gaps does not create these, but a Settings-app
  # click might have, and the symptom looks identical.
  $ifDoh = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
  if (Test-Path $ifDoh) {
    $hits = Get-ChildItem $ifDoh -Recurse -EA SilentlyContinue |
              Where-Object { $null -ne (Get-ItemProperty $_.PSPath -EA SilentlyContinue).DohFlags }
    if ($hits) {
      Write-Warning "  $($hits.Count) per-interface DoH override(s) found:"
      $hits | ForEach-Object { "     $($_.PSPath -replace '.*InterfaceSpecificParameters\\','')" }
      Write-Warning "  Not removed automatically. Settings > Network > <adapter> > DNS server assignment > Edit > Unencrypted."
    }
  }

  if ($PSCmdlet.ShouldProcess('Dnscache', 'Restart and flush')) {
    # Dnscache often refuses a live stop on modern Windows; a reboot is the
    # reliable path, so treat failure here as expected, not alarming.
    try {
      Restart-Service Dnscache -Force -EA Stop
      "  Dnscache restarted"
    } catch {
      Write-Warning "  Could not restart Dnscache live - REBOOT to apply. ($($_.Exception.Message))"
    }
    ipconfig /flushdns | Out-Null
    "  DNS cache flushed"
  }
}

# ================================================================ SECTION B
if ($BitLocker) {
  Write-Host "`n==== REVERT SECTION B: BitLocker pre-boot PIN policy ====" -ForegroundColor Cyan
  Write-Host "  This removes the POLICY only. It does NOT remove a TPMAndPIN protector" -ForegroundColor Yellow
  Write-Host "  you already added, and it does NOT decrypt the drive." -ForegroundColor Yellow
  Write-Host "  CONFIRM YOU HAVE YOUR RECOVERY KEY OFFLINE BEFORE CHANGING ANYTHING BITLOCKER." -ForegroundColor Red

  if (Test-Path $fve) {
    $reg = if ($BackupPath) { Join-Path $BackupPath 'HKLM_SOFTWARE_Policies_Microsoft_FVE.reg' }
    if ($reg -and (Test-Path $reg)) {
      if ($PSCmdlet.ShouldProcess($fve, 'Import original FVE policy')) {
        reg.exe import $reg | Out-Null
        "  Imported original FVE policy"
      }
    } else {
      # No backup export means the key did not exist before Fix-Gaps created it,
      # so removing the four values Section B wrote is the faithful revert.
      foreach ($v in 'UseAdvancedStartup','EnableBDEWithNoTPM','UseTPMPIN','UseTPM') {
        if ($PSCmdlet.ShouldProcess("$fve\$v", 'Remove value')) {
          Remove-ItemProperty $fve -Name $v -EA SilentlyContinue
          "  Removed $v"
        }
      }
    }
  } else { "  No FVE policy key present - nothing to revert" }

  $rkFile = 'C:\Users\User\BitLocker-Recovery-C.txt'
  if (Test-Path $rkFile) {
    Write-Warning "  Recovery key file still on the encrypted drive: $rkFile"
    Write-Warning "  Move it to offline storage, then delete it manually. Not deleted automatically."
  }
  "  Current protectors:"
  manage-bde -protectors -get C: | Select-String 'Key Protector|Numerical|TPM' | ForEach-Object { "    $_" }
}

# ================================================================ SECTION A
if ($Accounts) {
  Write-Host "`n==== REVERT SECTION A: accounts ====" -ForegroundColor Cyan
  Write-Host "  Reverting password policy WEAKENS this machine. Skip unless it is" -ForegroundColor Yellow
  Write-Host "  actually blocking you." -ForegroundColor Yellow

  # Windows stock defaults: min length 0, max age 42 days.
  if ($PSCmdlet.ShouldProcess('local password policy', 'Reset to Windows defaults')) {
    net accounts /minpwlen:0 /maxpwage:42 | Out-Null
    "  Password policy reset to defaults (minlen 0, maxage 42)"
  }

  # Left OFF by default - these were disabled for good reason. Uncomment only if
  # you genuinely need the account back.
  Write-Host "  'Kusum Singh' / 'Guest' / built-in Administrator left DISABLED." -ForegroundColor Yellow
  Write-Host "  To re-enable one:  Enable-LocalUser -Name 'Kusum Singh'" -ForegroundColor Yellow

  Get-LocalUser | Select-Object Name,Enabled,PasswordRequired | Format-Table -AutoSize
}

# ==================================================================== verify
Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
$after = Get-DnsHealth
$after | Format-List

if ($RepairDns) {
  if ($after.Resolves) {
    Write-Host "DNS is resolving again." -ForegroundColor Green
  } else {
    Write-Host @"
DNS still failing. If Dnscache would not restart live, REBOOT first - that fixes
most cases. If it still fails after a reboot, the service key is fine but
something else is wrong; check in this order:
  Get-Service Dnscache                       # must be Running
  Get-DnsClientServerAddress -AddressFamily IPv4
  Test-NetConnection 1.1.1.1 -Port 53
  Resolve-DnsName microsoft.com -Server 1.1.1.1
"@ -ForegroundColor Red
  }
}
Write-Host "`nSection C (Java uninstall) is NOT reversible - reinstall from the vendor if needed." -ForegroundColor Yellow
