<#
    Block-HpSmartInternet.ps1  -  let HP Smart reach the LAN, not the internet.

    RUN IN AN ELEVATED (Administrator) PowerShell for -Apply / -Revert.

    WHY IT IS BUILT THIS WAY - the important bit
    You CANNOT express this as "block everything, then allow the LAN". Windows
    Firewall evaluates Block before Allow, so a broad block rule swallows any
    LAN allow rule you add next to it. (The only exception is an authenticated
    IPsec bypass rule, which needs domain IPsec and does not apply here.)

    So this is ONE block rule whose RemoteAddress is the complement of the
    local address space - everything except RFC1918, loopback, link-local,
    multicast and broadcast. Traffic to the LAN never matches the rule at all,
    so it is allowed by the profile default (DefaultOutboundAction=Allow).

    LEFT REACHABLE on purpose:
      10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16   RFC1918 - your printer
      169.254.0.0/16                              link-local / APIPA
      127.0.0.0/8                                 loopback
      224.0.0.0/4                                 multicast - incl. 224.0.0.251
                                                  mDNS and 239.255.255.250 SSDP,
                                                  which is how HP Smart finds
                                                  printers. Blocking these would
                                                  break local discovery.
      255.255.255.255                             broadcast
      IPv6 fe80::/10, fc00::/7, ff00::/8, ::1     link-local, ULA, multicast

    BLOCKED: everything else, expressed as 7 IPv4 ranges plus 2000::/3, which
    is the whole IPv6 global unicast space.

    TWO RULES, because it is a packaged (MSIX) app
      1. Program rule keyed on the HP.Smart.exe path. The manifest declares
         runFullTrust, so its full-trust processes match a normal path rule.
      2. Package rule keyed on the AppContainer SID. Traffic from the sandboxed
         side of a packaged app is NOT reliably matched by a path rule, so the
         package rule is what actually catches it.
      Use -ProgramOnly to skip rule 2. Be aware rule 2 is a SUPERSET of what
      was asked for: it covers every process running under the package
      identity, which includes the DesktopExtension helpers
      (HPPrinterHealthMonitor.exe, HPSUPD-Win32Exe.exe, WinGetDownloader.exe).
      That is usually what you want; it is not literally "HP.Smart.exe only".

    NOT DISABLED, deliberately: HP's own pre-existing "HP Smart" Allow rules
    are left in place. Block wins over Allow, so they are already inert for
    internet destinations, and leaving them means -Revert restores the original
    state exactly by deleting only what this script created.

    WHAT BREAKS: anything HP Smart does over the internet - HP account sign-in,
    Instant Ink, cloud print, firmware update checks, telemetry and upsell.
    Local printing, scanning, ink levels and printer status over the LAN keep
    working.

    MODES
      (no switches)   Read-only: rules present, and what they cover.
      -Apply          Create the rules under a single named group.
      -Revert         Delete every rule in that group. Needs no state file.
      -ProgramOnly    Create only the path-based rule.
      -WhatIf         Show what would change, change nothing.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $Apply,
    [switch] $Revert,
    [switch] $ProgramOnly
)

$ErrorActionPreference = 'Stop'
$Group   = 'SecureVault - HP Smart LAN only'
$PkgName = 'AD2F1837.HPPrinterControl'

# Complement of RFC1918 + loopback + link-local + multicast + broadcast.
$InternetV4 = @(
    '1.0.0.0-9.255.255.255'
    '11.0.0.0-126.255.255.255'
    '128.0.0.0-169.253.255.255'
    '169.255.0.0-172.15.255.255'
    '172.32.0.0-192.167.255.255'
    '192.169.0.0-223.255.255.255'
    '240.0.0.0-255.255.255.254'
)
$InternetV6 = @('2000::/3')
$Internet   = $InternetV4 + $InternetV6

function Get-HpBits {
    $pkg = Get-AppxPackage -Name $PkgName -ErrorAction SilentlyContinue
    if (-not $pkg) { throw "$PkgName is not installed." }
    $exe = Join-Path $pkg.InstallLocation 'HP.Smart.exe'
    if (-not (Test-Path $exe)) { throw "HP.Smart.exe not found under $($pkg.InstallLocation)." }

    $base = 'HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
    $sid = $null
    Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
        if ((Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Moniker -eq $pkg.PackageFamilyName) {
            $sid = $_.PSChildName
        }
    }
    [pscustomobject]@{ Exe = $exe; FamilyName = $pkg.PackageFamilyName; Sid = $sid }
}

function Get-OurRules { Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue }

function Show-Status {
    $hp = Get-HpBits
    ''
    "  HP.Smart.exe : $($hp.Exe)"
    "  Package SID  : $(if ($hp.Sid) { $hp.Sid } else { '(not found - package rule unavailable)' })"
    ''
    $rules = @(Get-OurRules)
    if ($rules.Count -eq 0) {
        'No rules from this script are present. HP Smart can reach the internet.'
        'Run with -Apply (elevated) to restrict it to the LAN.'
        ''
        return
    }
    "  Rules in group '$Group':"
    foreach ($r in $rules) {
        $af = $r | Get-NetFirewallAddressFilter
        $n  = @($af.RemoteAddress).Count
        "    {0,-46} {1,-6} {2,-8} {3} remote ranges" -f $r.DisplayName, $r.Action, $(if ($r.Enabled -eq 'True') { 'enabled' } else { 'DISABLED' }), $n
    }
    ''
    'HP Smart is restricted to LAN destinations.'
    ''
}

function Assert-Admin {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
                  [Security.Principal.WindowsIdentity]::GetCurrent())
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $WhatIfPreference) {
        throw 'Not elevated. Firewall rule changes need Administrator. Re-run from an elevated PowerShell.'
    }
    if (-not $isAdmin) { 'NOTE: not elevated - -WhatIf only. A real run needs Administrator.' }
}

# ---------------------------------------------------------------- status ----
if (-not $Apply -and -not $Revert) { Show-Status; return }
if ($Apply -and $Revert) { throw 'Pass -Apply or -Revert, not both.' }
Assert-Admin

# ----------------------------------------------------------------- apply ----
if ($Apply) {
    $hp = Get-HpBits

    $existing = @(Get-OurRules)
    if ($existing.Count -gt 0) {
        "Removing $($existing.Count) pre-existing rule(s) in this group first, so -Apply is idempotent."
        if ($PSCmdlet.ShouldProcess($Group, 'Remove existing rules in group')) {
            Remove-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue
        }
    }

    if ($PSCmdlet.ShouldProcess('HP Smart - block internet (program)', 'Create outbound block rule')) {
        $null = New-NetFirewallRule `
            -DisplayName  'HP Smart - block internet (program)' `
            -Group        $Group `
            -Direction    Outbound `
            -Action       Block `
            -Enabled      True `
            -Profile      Any `
            -Program      $hp.Exe `
            -RemoteAddress $Internet `
            -Description  'Blocks HP.Smart.exe to all non-local destinations. LAN, loopback, link-local and multicast are not matched, so they stay allowed.'
        '  OK       program rule created'
    }

    if (-not $ProgramOnly) {
        if (-not $hp.Sid) {
            '  SKIP     package rule - no AppContainer SID found for the package'
        }
        elseif ($PSCmdlet.ShouldProcess('HP Smart - block internet (package)', 'Create outbound block rule')) {
            $null = New-NetFirewallRule `
                -DisplayName  'HP Smart - block internet (package)' `
                -Group        $Group `
                -Direction    Outbound `
                -Action       Block `
                -Enabled      True `
                -Profile      Any `
                -Package      $hp.Sid `
                -RemoteAddress $Internet `
                -Description  'Blocks the HP Printer Control package identity to all non-local destinations. Covers AppContainer traffic a path rule would miss.'
            '  OK       package rule created'
        }
    }

    if ($WhatIfPreference) { return }

    ''
    'Verifying against a fresh read of the firewall store...'
    $made = @(Get-OurRules)
    if ($made.Count -eq 0) {
        throw 'No rules were created. Nothing changed.'
    }
    foreach ($r in $made) {
        $af  = $r | Get-NetFirewallAddressFilter
        $apf = $r | Get-NetFirewallApplicationFilter
        $ok  = ($r.Action -eq 'Block') -and ($r.Enabled -eq 'True') -and (@($af.RemoteAddress).Count -eq $Internet.Count)
        if (-not $ok) {
            "  BAD      $($r.DisplayName) did not materialise as expected - rolling back"
            Remove-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue
            throw "Rule verification failed. All rules in '$Group' removed; nothing left half-applied."
        }
        "  verified $($r.DisplayName)"
        "             ranges: $(@($af.RemoteAddress) -join '  ')"
        if ($apf.Program -and $apf.Program -ne 'Any')     { "             program: $($apf.Program)" }
        if ($apf.Package -and $apf.Package -ne 'Any')     { "             package: $($apf.Package)" }
    }

    Show-Status
    'Functional check: launch HP Smart and confirm it still sees the printer but'
    'cannot reach HP cloud features. It is normal for sign-in / Instant Ink to fail.'
    "Revert with:  .\Block-HpSmartInternet.ps1 -Revert"
    return
}

# ---------------------------------------------------------------- revert ----
if ($Revert) {
    $rules = @(Get-OurRules)
    if ($rules.Count -eq 0) { 'Nothing to revert - no rules from this script are present.'; return }
    if ($PSCmdlet.ShouldProcess($Group, "Remove $($rules.Count) rule(s)")) {
        Remove-NetFirewallRule -Group $Group
        "  OK       removed $($rules.Count) rule(s)"
    }
    if ($WhatIfPreference) { return }
    ''
    "Remaining rules in group: $(@(Get-OurRules).Count)"
    'HP Smart can reach the internet again. HP''s own Allow rules were never touched.'
    ''
    return
}
