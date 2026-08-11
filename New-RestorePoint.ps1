<#
    New-RestorePoint.ps1  -  enable System Restore and take a checkpoint
    RUN IN AN ELEVATED (Administrator) PowerShell.

    Run this BEFORE Harden-Laptop.ps1 / Fix-Gaps.ps1 every time.
    System Restore rolls back the registry hives, services config and firewall
    rules - which is precisely what those two scripts change - so it would have
    recovered both the DNS and the Wi-Fi breakage.

    It does NOT roll back: your documents, uninstalled programs' data,
    BitLocker state, or anything outside the protected volume.
#>

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Not elevated. Re-run this in an Administrator PowerShell."
}

Write-Host "`n==== 1. Enable System Restore on C: ====" -ForegroundColor Cyan
Enable-ComputerRestore -Drive "C:\"
"System Restore enabled for C:\"

Write-Host "`n==== 2. Give it disk space (10% of C:) ====" -ForegroundColor Cyan
# Default allocation can be tiny; too small and Windows silently deletes old points.
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=10%

Write-Host "`n==== 3. Remove the 24-hour throttle ====" -ForegroundColor Cyan
# By default Windows silently SKIPS a new restore point if one was made in the
# last 24h - Checkpoint-Computer then "succeeds" without creating anything.
$sr = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
if (-not (Test-Path $sr)) { New-Item $sr -Force | Out-Null }   # only when missing
Set-ItemProperty $sr 'SystemRestorePointCreationFrequency' 0 -Type DWord
"Frequency throttle disabled (0 = always create)"

Write-Host "`n==== 4. Create the restore point ====" -ForegroundColor Cyan
$desc = "Pre-hardening $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Checkpoint-Computer -Description $desc -RestorePointType MODIFY_SETTINGS
"Created: $desc"

Write-Host "`n==== 5. Verify (this is the part that matters) ====" -ForegroundColor Cyan
$points = Get-ComputerRestorePoint
if (-not $points) {
    Write-Host "NO RESTORE POINTS EXIST. Do NOT run the hardening scripts." -ForegroundColor Red
} else {
    $points | Select-Object SequenceNumber,
        @{n='CreationTime';e={$_.ConvertToDateTime($_.CreationTime)}},
        Description | Format-Table -AutoSize
    Write-Host "Confirm your new point is listed above before hardening." -ForegroundColor Green
}

<#  ===================== HOW TO ROLL BACK =====================

If the machine still boots and you can log in:
    rstrui.exe                      # pick the point, follow the wizard
  or from an elevated prompt:
    Restore-Computer -RestorePoint <SequenceNumber>

If the machine boots but has NO network (your exact previous situation):
    rstrui.exe still works - it is entirely local, no network needed.

If Windows will not boot:
    Hold Shift while clicking Restart (or power-cycle 3x to force WinRE)
    -> Troubleshoot -> Advanced options -> System Restore

BitLocker note: with a pre-boot PIN enabled, WinRE will ask for your
recovery key before it lets you restore. Keep that key offline and reachable.
============================================================== #>
