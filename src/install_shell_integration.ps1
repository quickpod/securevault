<#
  SecureVault shell integration installer.

  Adds a right-click "Send to SV (Secure Vault)" entry to Explorer for files
  and folders, wired to SecureVault.exe ... add "<path>".  It also registers a
  "SecureVault" entry so you can open the browser from a folder background.

  Run from the folder that contains SecureVault.exe.  No admin rights needed -
  everything is written under HKCU (per-user).  Uninstall with -Remove.
#>
param(
    [string]$ExePath = (Join-Path $PSScriptRoot 'SecureVault.exe'),
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$icon = "`"$ExePath`",0"

# key path, command, whether it's a background (folder) verb
$verbs = @(
    @{ Root = 'HKCU:\Software\Classes\*\shell\SecureVaultAdd';           Cmd = "`"$ExePath`" add `"%1`"";     Label = 'Send to SV (Secure Vault)' },
    @{ Root = 'HKCU:\Software\Classes\Directory\shell\SecureVaultAdd';   Cmd = "`"$ExePath`" add `"%1`"";     Label = 'Send folder to SV (Secure Vault)' },
    @{ Root = 'HKCU:\Software\Classes\Directory\Background\shell\SecureVault'; Cmd = "`"$ExePath`"";           Label = 'Open Secure Vault' }
)

if ($Remove) {
    foreach ($v in $verbs) { if (Test-Path $v.Root) { Remove-Item $v.Root -Recurse -Force } }
    Write-Host "SecureVault shell integration removed."
    return
}

if (-not (Test-Path $ExePath)) { throw "SecureVault.exe not found at: $ExePath" }

foreach ($v in $verbs) {
    New-Item -Path $v.Root -Force | Out-Null
    New-ItemProperty -Path $v.Root -Name '(default)' -Value $v.Label -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $v.Root -Name 'Icon'      -Value $icon    -PropertyType String -Force | Out-Null
    $cmdKey = Join-Path $v.Root 'command'
    New-Item -Path $cmdKey -Force | Out-Null
    New-ItemProperty -Path $cmdKey -Name '(default)' -Value $v.Cmd -PropertyType String -Force | Out-Null
}

Write-Host "SecureVault shell integration installed for the current user."
Write-Host "Right-click any file  -> 'Send to SV (Secure Vault)'"
Write-Host "Exe: $ExePath"
