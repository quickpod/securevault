<#
    Remove-StoreBloat.ps1  -  remove unused Store (MSIX) packages.

    RUN IN AN ELEVATED (Administrator) PowerShell for -Apply.
    Per-user removal works unelevated; DEPROVISIONING (so the package does not
    come back for a newly created user account) needs Administrator.

    WHY THIS EXISTS - AND WHAT IT IS NOT
    A port/binary audit on 2026-08-08 flagged HxTsr.exe as an "unsigned binary"
    dialling out. That was accurate but not suspicious: a scan of
    C:\Program Files\WindowsApps found 38 of 123 top-level EXEs across 31 of 98
    packages carry NO embedded Authenticode signature. That is how MSIX works -
    the PACKAGE is signed (SignatureKind=Store, publisher CN=Microsoft
    Corporation) and Windows enforces integrity through the package signature
    plus the TrustedInstaller-owned ACL on WindowsApps. Individual payload EXEs
    are routinely unsigned.

    So DO NOT delete unsigned files out of WindowsApps. Among them are
    Microsoft.WindowsStore (4 EXEs) and Microsoft.SecHealthUI (the Windows
    Security UI, flagged NonRemovable). Deleting files in place would leave
    packages registered but broken, require seizing ownership from
    TrustedInstaller, break servicing, and offer no clean undo - you cannot
    reinstall the Store from the Store.

    The correct unit of removal is the PACKAGE. That is what this script does.

    ALREADY DONE SEPARATELY, not by this script:
    microsoft.windowscommunicationsapps (Mail & Calendar - the HxTsr.exe owner)
    was removed and deprovisioned on 2026-08-08. Note Microsoft retired that app
    at the end of 2024 and pulled it from the Store, so it is likely NOT
    reinstallable. The others in $Targets below are ordinary Store apps.

    MODES
      (no switches)   Read-only: which targets are present, and their unsigned
                      EXE count.
      -Apply          Remove each target for all users and deprovision it.
                      Records what was removed to C:\SecureVault\Backups first.
      -Revert         Best effort reinstall. Tries Add-AppxPackage
                      -RegisterByFamilyName for anything still staged on disk;
                      for the rest it prints the names to reinstall from the
                      Store. Deprovisioned Store apps cannot always be restored
                      offline - this is the one change here that is not
                      guaranteed reversible without network.
      -WhatIf         Show what would change, change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $Apply,
    [switch] $Revert
)

$ErrorActionPreference = 'Stop'
$BackupDir = 'C:\SecureVault\Backups'

$Targets = @(
    'Microsoft.BingNews'
    'Microsoft.BingWeather'
    'Microsoft.MicrosoftSolitaireCollection'
    'Microsoft.People'
    'Microsoft.Todos'
    'Microsoft.Windows.DevHome'
    'Microsoft.WindowsMaps'
    'Microsoft.ZuneMusic'
    'Microsoft.ZuneVideo'
    'MicrosoftCorporationII.MicrosoftFamily'
    'MicrosoftWindows.CrossDevice'
    'Microsoft.Xbox.TCUI'
    'Microsoft.XboxGameOverlay'
    'Microsoft.XboxIdentityProvider'
    'Microsoft.XboxSpeechToTextOverlay'
)

# Never remove these even if they somehow appear in $Targets.
$Protected = @('Microsoft.WindowsStore','Microsoft.SecHealthUI','Microsoft.StorePurchaseApp','Microsoft.DesktopAppInstaller','Microsoft.VCLibs','Microsoft.UI.Xaml')

function Get-TargetState {
    foreach ($t in $Targets) {
        $p = Get-AppxPackage -Name $t -ErrorAction SilentlyContinue | Select-Object -First 1
        $unsigned = 0
        if ($p -and $p.InstallLocation -and (Test-Path $p.InstallLocation)) {
            $unsigned = @(Get-ChildItem $p.InstallLocation -Filter '*.exe' -ErrorAction SilentlyContinue |
                          Where-Object { (Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue).Status -ne 'Valid' }).Count
        }
        [pscustomobject]@{
            Package      = $t
            Present      = [bool]$p
            FullName     = $(if ($p) { $p.PackageFullName } else { '' })
            FamilyName   = $(if ($p) { $p.PackageFamilyName } else { '' })
            NonRemovable = $(if ($p) { $p.NonRemovable } else { $null })
            UnsignedExes = $unsigned
        }
    }
}

function Assert-Admin {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
                  [Security.Principal.WindowsIdentity]::GetCurrent())
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $WhatIfPreference) {
        throw 'Not elevated. Deprovisioning needs Administrator. Re-run from an elevated PowerShell.'
    }
    if (-not $isAdmin) { 'NOTE: not elevated - -WhatIf only. A real run needs Administrator.' }
}

# ---------------------------------------------------------------- status ----
$state = @(Get-TargetState)

if (-not $Apply -and -not $Revert) {
    ''
    '{0,-42} | {1,-8} | {2}' -f 'PACKAGE','PRESENT','UNSIGNED EXES'
    '{0,-42} | {1,-8} | {2}' -f ('-'*42),('-'*8),('-'*13)
    foreach ($s in $state) { '{0,-42} | {1,-8} | {2}' -f $s.Package, $s.Present, $s.UnsignedExes }
    ''
    $present = @($state | Where-Object Present)
    "$($present.Count) of $($Targets.Count) targets present, $(($present | Measure-Object UnsignedExes -Sum).Sum) unsigned EXEs between them."
    if ($present.Count) { 'Run with -Apply (elevated) to remove them.' }
    ''
    return
}
if ($Apply -and $Revert) { throw 'Pass -Apply or -Revert, not both.' }
Assert-Admin

# ----------------------------------------------------------------- apply ----
if ($Apply) {
    $todo = @($state | Where-Object { $_.Present -and $Protected -notcontains $_.Package })
    if ($todo.Count -eq 0) { 'Nothing to do - no target package is installed.'; return }

    if (-not (Test-Path $BackupDir)) { $null = New-Item -ItemType Directory -Path $BackupDir -Force }
    $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $record = Join-Path $BackupDir "appx-removed-$stamp.json"

    if ($PSCmdlet.ShouldProcess($record, 'Record packages before removal')) {
        $todo | ConvertTo-Json -Depth 4 | Out-File -FilePath $record -Encoding utf8
        "Record saved: $record"
        ''
    }

    foreach ($t in $todo) {
        if (-not $PSCmdlet.ShouldProcess($t.Package, 'Remove for all users + deprovision')) { continue }

        try   { Remove-AppxPackage -Package $t.FullName -AllUsers -ErrorAction Stop; "  OK       removed   $($t.Package)" }
        catch { "  note     remove    $($t.Package): $($_.Exception.Message -replace '\s+',' ')" }

        try {
            $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $t.Package }
            if ($prov) {
                Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                "  OK       deprov    $($t.Package)"
            }
        }
        catch { "  note     deprov    $($t.Package): $($_.Exception.Message -replace '\s+',' ')" }
    }

    if ($WhatIfPreference) { return }

    ''
    'Verifying against a fresh read of the package store...'
    $after = @(Get-TargetState)
    $left  = @($after | Where-Object Present)
    $prov  = @(Get-AppxProvisionedPackage -Online | Where-Object { $Targets -contains $_.DisplayName })
    ''
    "  still installed  : $($left.Count)  $(if($left){'-> ' + ($left.Package -join ', ')})"
    "  still provisioned: $($prov.Count)  $(if($prov){'-> ' + ($prov.DisplayName -join ', ')})"
    ''
    'Protected and untouched: ' + ($Protected -join ', ')
    "Revert with:  .\Remove-StoreBloat.ps1 -Revert"
    return
}

# ---------------------------------------------------------------- revert ----
if ($Revert) {
    $newest = $null
    if (Test-Path $BackupDir) {
        $newest = Get-ChildItem -Path $BackupDir -Filter 'appx-removed-*.json' -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    $names = $Targets
    if ($newest) {
        try {
            $rec = Get-Content -LiteralPath $newest.FullName -Raw | ConvertFrom-Json
            if ($rec) { $names = @($rec.Package); "Using the record in $($newest.Name)." }
        } catch { }
    }
    if (-not $newest) { 'No removal record found. Falling back to the full target list.' }

    $restored = @(); $manual = @()
    foreach ($n in $names) {
        if (Get-AppxPackage -Name $n -ErrorAction SilentlyContinue) { "  skip     $n (already installed)"; continue }
        if (-not $PSCmdlet.ShouldProcess($n, 'Re-register from staged files')) { continue }
        $staged = Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($staged) {
            try   { Add-AppxPackage -RegisterByFamilyName -MainPackage $staged.PackageFamilyName -ErrorAction Stop
                    "  OK       re-registered $n"; $restored += $n }
            catch { "  FAILED   $n - reinstall from the Store"; $manual += $n }
        } else { $manual += $n }
    }

    if ($WhatIfPreference) { return }

    ''
    "Re-registered from disk: $($restored.Count)"
    if ($manual.Count) {
        'Not restorable offline - reinstall these from the Microsoft Store by name:'
        $manual | ForEach-Object { "    $_" }
    }
    ''
    return
}
