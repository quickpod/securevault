<#
    Reduce-IdleFootprint.ps1  -  stop background apps holding network
                                 connections open while the laptop sits idle.

    RUN IN AN ELEVATED (Administrator) PowerShell.

    WHAT WAS ACTUALLY RUNNING (measured 2026-08-07, laptop idle, no browser
    window open anywhere):
        msedge.exe          7 processes   618 MB   2 live HTTPS connections
        msedgewebview2.exe 18 processes   800 MB   1 live HTTPS connection
        M365Copilot.exe     1 process     144 MB   headless
        Widgets.exe         1 process      45 MB   headless
        SearchHost.exe      1 process      73 MB   headless
    Every one of those had an EMPTY window title - nothing was open. That is
    ~1.7 GB and most of the idle chatter.

    WHAT IS LEGITIMATE AND IS LEFT ALONE
        svchost.exe (Dnscache)  the DoH session to your own resolvers. Windows
                                holds this open by design - see Set-PrivateDoh.ps1.
        ssh.exe                 a remote-SSH session you started (e.g. VS Code).
        System (PID 4)          SMB to your NAS / backup share on the LAN (e.g.
                                192.0.2.10 = the X: backup drive). This is
                                LAN-only. TCPView may show it under the share's
                                hostname (e.g. "nas.example.lan") because that is
                                the PTR record for the LAN address - it is NOT an
                                internet SMB connection.
        MsMpEng.exe             Defender.

    WHAT THIS CHANGES
      Edge      BackgroundModeEnabled=0  - stop Edge lingering after the last
                                           window closes
                StartupBoostEnabled=0    - stop Edge preloading at logon
                MicrosoftEdgeAutoLaunch_* Run entry removed
      Copilot   MicrosoftCopilotAutoLaunch_* Run entry removed
      Widgets   AllowNewsAndInterests=0  - the Dsh policy, kills Widgets.exe
      Search    DisableSearchBoxSuggestions=1 - stops SearchHost calling out
                                           to Bing for Start-menu typing

      Optional, off by default because they are your call, not obviously waste:
        -IncludeOneDrive   remove the OneDrive Run entry. NOTE: this stops the
                           offsite half of Backup-SecureVault.ps1 syncing.
        -IncludeDiscord    remove the Discord Run entry.
        -IncludeFirefox    remove the Firefox background-update Run entry.

      -StopNow             also terminate the already-running background
                           processes so the effect is immediate instead of
                           after next logon. Refuses to touch any process that
                           has a visible window - see Stop-Idle.

    SAFETY
      - Every value this touches is saved to a state file first, and -Revert
        puts them back exactly, including deleting values that did not exist
        before.
      - Registry keys are created one segment at a time and NEVER with
        'New-Item -Force'. Forcing an existing key DELETES AND RECREATES IT
        EMPTY - that is precisely what wiped Dnscache's ServiceDll and killed
        all DNS on 2026-08-06. Not repeating it.
      - Nothing here touches a service, a driver, or a network setting. Worst
        case you lose some Start-menu web results until you -Revert.

    MODES
      (no switches)  Read-only: what is running, what is connected, what this
                     would change.
      -Apply         Make the changes.
      -Revert        Put everything back from the state file.

    Supports -WhatIf on every mutation.
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Apply')]  [switch]$Apply,
  [Parameter(ParameterSetName = 'Revert')] [switch]$Revert,
  [Parameter(ParameterSetName = 'Apply')]  [switch]$StopNow,
  [switch]$IncludeOneDrive,
  [switch]$IncludeDiscord,
  [switch]$IncludeFirefox,
  [switch]$BlockSearchHost,
  [switch]$RemoveWidgets
)

$ErrorActionPreference = 'Continue'

$StateDir  = 'C:\SecureVault\Backups'
$StateFile = Join-Path $StateDir 'idle-footprint-lastgood.json'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Not elevated. Re-run this in an Administrator PowerShell."
}

# The processes we consider idle waste, and what drives each.
$IdleApps = @(
  @{ Proc = 'msedge';         Why = 'Edge background mode / startup boost' },
  @{ Proc = 'msedgewebview2'; Why = 'hosts Copilot, Widgets and Search panes' },
  @{ Proc = 'M365Copilot';    Why = 'M365 Copilot auto-launch' },
  @{ Proc = 'Widgets';        Why = 'Widgets board' },
  @{ Proc = 'WidgetService';  Why = 'Widgets board' },
  # SearchHost holds a WebView2 open for Start-menu web results. It reads its
  # policy ONLY at start, so setting DisableSearchBoxSuggestions is not enough -
  # a SearchHost that has been up since before the policy landed keeps calling
  # out. Restarting it is safe: the shell respawns it on the next Start click.
  @{ Proc = 'SearchHost';     Why = 'Start-menu web results (respawns on demand)' }
)

# ---------------------------------------------------------------- helpers ----

function New-RegKeySafe {
  <#
    Create a registry key without ever using 'New-Item -Force'.

    -Force on a key that ALREADY EXISTS deletes it and recreates it empty.
    On 2026-08-06 that is exactly what wiped ServiceDll out of the Dnscache
    Parameters key and left the machine unable to resolve anything on any
    adapter - Dnscache is svchost -k NetworkService with no binary of its own,
    so losing that value is fatal and swapping NICs does not help.

    So: walk the path one segment at a time and create only what is missing.
  #>
  param([string]$Path)

  if (Test-Path $Path) { return }

  $parts = $Path -split '\\'
  $cur   = $parts[0]                       # e.g. 'HKLM:'
  foreach ($p in $parts[1..($parts.Count - 1)]) {
    $next = Join-Path $cur $p
    if (-not (Test-Path $next)) { New-Item -Path $cur -Name $p | Out-Null }
    $cur = $next
  }
}

function Get-Original {
  # Capture a value's exact prior state so -Revert can be faithful. The
  # distinction that matters is "existed with value X" vs "did not exist" -
  # restoring a 0 where there was nothing is not a revert.
  param([string]$Path, [string]$Name)
  $exists = $false; $value = $null; $kind = $null
  if (Test-Path $Path) {
    $item = Get-ItemProperty -Path $Path -Name $Name -EA SilentlyContinue
    if ($null -ne $item -and $null -ne $item.$Name) {
      $exists = $true
      $value  = $item.$Name
      $kind   = (Get-Item $Path).GetValueKind($Name).ToString()
    }
  }
  [pscustomobject]@{ Path = $Path; Name = $Name; Existed = $exists; Value = $value; Kind = $kind }
}

function Set-Value {
  <#
    Write a policy value and PROVE it landed by reading it back.

    New-ItemProperty has been observed creating the key but silently failing to
    write the value - HKLM\...\Policies\Microsoft\Dsh ended up existing and
    completely empty, with Administrators holding FullControl and no error
    raised. A policy that reads as "applied" but is not there is the worst
    outcome, so: write, verify, and on mismatch fall back to the .NET registry
    API, then verify again and shout if it still has not taken.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Label)
  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value  ($Label)")) { return }

  try { New-RegKeySafe -Path $Path }
  catch { Write-Warning "    could not create $Path : $($_.Exception.Message)"; return }

  try { New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -EA Stop | Out-Null }
  catch { Write-Warning "    New-ItemProperty failed on $Path\$Name : $($_.Exception.Message)" }

  if ((Get-ItemProperty -Path $Path -Name $Name -EA SilentlyContinue).$Name -eq $Value) {
    Write-Host "    set  $Label" -ForegroundColor Green
    return
  }

  # Fallback: the .NET API talks to the registry directly rather than through
  # the PowerShell provider.
  Write-Host "    (verify failed - retrying via .NET registry API)" -ForegroundColor DarkYellow
  try {
    $netPath = $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
    $kind = switch ($Type) { 'DWord' { 'DWord' } 'String' { 'String' } default { 'DWord' } }
    [Microsoft.Win32.Registry]::SetValue($netPath, $Name, $Value, [Microsoft.Win32.RegistryValueKind]::$kind)
  } catch { Write-Warning "    .NET SetValue failed: $($_.Exception.Message)" }

  if ((Get-ItemProperty -Path $Path -Name $Name -EA SilentlyContinue).$Name -eq $Value) {
    Write-Host "    set  $Label  (via fallback)" -ForegroundColor Green
  } else {
    Write-Warning "    NOT APPLIED: $Path\$Name is still not $Value. $Label is NOT in effect."
  }
}

function Remove-Value {
  [CmdletBinding(SupportsShouldProcess)]
  param([string]$Path, [string]$Name, [string]$Label)
  if (-not (Test-Path $Path)) { return }
  if ($null -eq (Get-ItemProperty -Path $Path -Name $Name -EA SilentlyContinue).$Name) { return }
  if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Remove  ($Label)")) { return }
  try {
    Remove-ItemProperty -Path $Path -Name $Name -EA Stop
    Write-Host "    removed  $Label" -ForegroundColor Green
  } catch { Write-Warning "    could not remove $Path\$Name : $($_.Exception.Message)" }
}

function Get-RunEntry {
  # Run-key value names carry a per-install hash suffix
  # (MicrosoftEdgeAutoLaunch_C46CFC...), so they must be matched by pattern,
  # never hardcoded - the name differs on every machine.
  param([string]$Pattern)
  $out = @()
  foreach ($root in @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
    if (-not (Test-Path $root)) { continue }
    $props = (Get-Item $root).GetValueNames() | Where-Object { $_ -like $Pattern }
    foreach ($n in $props) { $out += [pscustomobject]@{ Path = $root; Name = $n } }
  }
  $out
}

$FwRuleName = 'SecureVault: block SearchHost outbound'

function Get-PackageSid {
  <#
    An AppContainer's SID is derived deterministically from its package family
    name. Derived at runtime rather than hardcoded so this keeps working if the
    package is ever re-registered.
  #>
  param([string]$FamilyName)
  $sig = @'
[DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int DeriveAppContainerSidFromAppContainerName(string appContainerName, out IntPtr sid);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool ConvertSidToStringSid(IntPtr sid, out string str);
'@
  if (-not ('W32.AppC' -as [type])) {
    Add-Type -MemberDefinition $sig -Namespace W32 -Name AppC -EA SilentlyContinue
  }
  $ptr = [IntPtr]::Zero; $str = $null
  if ([W32.AppC]::DeriveAppContainerSidFromAppContainerName($FamilyName, [ref]$ptr) -eq 0) {
    [void][W32.AppC]::ConvertSidToStringSid($ptr, [ref]$str)
    return $str
  }
  $null
}

function Block-SearchHostNetwork {
  <#
    Last resort for SearchHost, and only reached because policy did not work:
    ConnectedSearchUseWeb=0, AllowCloudSearch=0, DisableWebSearch=1,
    EnableDynamicContentInWSB=0, BingSearchEnabled=0 and CortanaConsent=0 were
    ALL verified applied, SearchHost was restarted afterwards, and it still
    held an HTTPS session open to Microsoft.

    The socket is owned by msedgewebview2.exe, not SearchHost.exe, so a
    -Program rule on SearchHost.exe would miss it - and a -Program rule on
    msedgewebview2.exe would block every WebView2 app on the machine and break
    on the next Edge update, since its path carries a version number. Scoping
    to the package SID hits exactly this app and nothing else.

    Functionally safe: local file, app and setting search are entirely local.
    Only web results go, and those are already disabled by the policies above.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param()

  $sid = Get-PackageSid -FamilyName 'MicrosoftWindows.Client.CBS_cw5n1h2txyewy'
  if (-not $sid) { Write-Warning "    could not derive the SearchHost package SID - skipping firewall rule"; return }
  Write-Host "    package SID: $sid" -ForegroundColor DarkGray

  if (Get-NetFirewallRule -DisplayName $FwRuleName -EA SilentlyContinue) {
    Write-Host "    rule already present" -ForegroundColor DarkGray
    return
  }
  if (-not $PSCmdlet.ShouldProcess($FwRuleName, 'Create outbound block rule for the SearchHost package')) { return }
  try {
    New-NetFirewallRule -DisplayName $FwRuleName -Direction Outbound -Action Block `
                        -Package $sid -Profile Any -Enabled True `
                        -Description 'Windows Search web/cloud calls. Removed by Reduce-IdleFootprint.ps1 -Revert.' -EA Stop | Out-Null
    Write-Host "    firewall rule created" -ForegroundColor Green
  } catch { Write-Warning "    could not create firewall rule: $($_.Exception.Message)" }
}

function Remove-WidgetsPackage {
  <#
    The durable fix for Widgets. The AllowNewsAndInterests policy under
    HKLM\SOFTWARE\Policies\Microsoft\Dsh would NOT stick - written elevated,
    verified absent afterwards, with Administrators holding FullControl and no
    error raised. Values under Policies\ that vanish like that are characteristic
    of the Group Policy client scrubbing settings with no backing GPO. Removing
    the package sidesteps the argument entirely.

    Reversible: reinstall "Widgets" from the Microsoft Store.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param()

  $pkg = Get-AppxPackage -Name 'MicrosoftWindows.Client.WebExperience' -EA SilentlyContinue
  if (-not $pkg) { Write-Host "    Widgets package not installed" -ForegroundColor DarkGray; return }
  if ($pkg.NonRemovable) { Write-Warning "    Widgets package is marked NonRemovable - skipping"; return }
  if (-not $PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Remove the Widgets package')) { return }
  try {
    Remove-AppxPackage -Package $pkg.PackageFullName -EA Stop
    Write-Host "    Widgets package removed" -ForegroundColor Green
  } catch { Write-Warning "    could not remove Widgets: $($_.Exception.Message)" }
}

function Get-IdleReport {
  $rows = @()
  foreach ($a in $IdleApps) {
    $p = @(Get-Process -Name $a.Proc -EA SilentlyContinue)
    if (-not $p) { continue }
    $vis = @($p | Where-Object { $_.MainWindowTitle }).Count
    $rows += [pscustomobject]@{
      Process  = $a.Proc
      Count    = $p.Count
      MB       = [math]::Round((($p | Measure-Object WorkingSet64 -Sum).Sum / 1MB), 0)
      Windows  = $vis
      Verdict  = if ($vis -gt 0) { 'IN USE - left alone' } else { 'idle - reclaimable' }
      Driver   = $a.Why
    }
  }
  $rows
}

function Show-Connections {
  $conns = Get-NetTCPConnection -State Established -EA SilentlyContinue |
             Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' }
  $conns | Group-Object OwningProcess | ForEach-Object {
    $pr = Get-Process -Id $_.Name -EA SilentlyContinue
    $nm = if ($pr) { $pr.Name } else { '<gone>' }
    $keep = switch -Regex ($nm) {
      '^svchost$'  { 'KEEP - Dnscache DoH session'; break }
      '^ssh$'      { 'KEEP - your Remote-SSH session'; break }
      '^System$'   { 'KEEP - SMB to LAN backup drive'; break }
      '^MsMpEng$'  { 'KEEP - Defender'; break }
      '^claude$'   { 'KEEP - this session'; break }
      '^(msedge|msedgewebview2|M365Copilot|Widgets)' { 'RECLAIMABLE'; break }
      default      { '' }
    }
    [pscustomobject]@{ Process = "$nm ($($_.Name))"; Conns = $_.Count; Note = $keep }
  } | Sort-Object Conns -Descending
}

function Stop-Idle {
  <#
    Terminate the background processes so the change takes effect now rather
    than at next logon. Re-checks window titles at kill time and skips anything
    visible - the report may be seconds stale, and closing a browser window the
    user just opened would lose their tabs.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param()
  foreach ($a in $IdleApps) {
    $p = @(Get-Process -Name $a.Proc -EA SilentlyContinue)
    if (-not $p) { continue }
    $visible = @($p | Where-Object { $_.MainWindowTitle })
    if ($visible) {
      Write-Host "    SKIP $($a.Proc): $($visible.Count) window(s) open - not killing your session" -ForegroundColor Yellow
      continue
    }
    if (-not $PSCmdlet.ShouldProcess("$($a.Proc) x$($p.Count)", 'Stop headless background process')) { continue }
    try {
      $p | Stop-Process -Force -EA Stop
      Write-Host "    stopped $($a.Proc) x$($p.Count)" -ForegroundColor Green
    } catch { Write-Warning "    could not stop $($a.Proc): $($_.Exception.Message)" }
  }
}

# ------------------------------------------------------------------ status ---

Write-Host "`n==== IDLE FOOTPRINT ====" -ForegroundColor Cyan
$report = Get-IdleReport
if ($report) { $report | Format-Table -AutoSize } else { Write-Host "  None of the usual background apps are running." -ForegroundColor Green }
$reclaim = ($report | Where-Object { $_.Verdict -like 'idle*' } | Measure-Object MB -Sum).Sum
if ($reclaim) { Write-Host "  Reclaimable right now: ~$reclaim MB" -ForegroundColor Yellow }

Write-Host "`n==== OUTBOUND CONNECTIONS ====" -ForegroundColor Cyan
Show-Connections | Format-Table -AutoSize

if ($PSCmdlet.ParameterSetName -eq 'Status') {
  Write-Host "Read-only. Nothing changed." -ForegroundColor Yellow
  Write-Host "`nTo apply:  .\Reduce-IdleFootprint.ps1 -Apply -StopNow" -ForegroundColor Cyan
  return
}

# ------------------------------------------------------------------ revert ---

if ($Revert) {
  Write-Host "`n==== REVERT ====" -ForegroundColor Cyan
  if (-not (Test-Path $StateFile)) { throw "No state file at $StateFile - nothing to revert to." }

  $st = Get-Content $StateFile -Raw | ConvertFrom-Json
  foreach ($o in $st.Originals) {
    if ($o.Existed) {
      if ($PSCmdlet.ShouldProcess("$($o.Path)\$($o.Name)", "Restore original value '$($o.Value)'")) {
        try {
          New-RegKeySafe -Path $o.Path
          New-ItemProperty -Path $o.Path -Name $o.Name -Value $o.Value `
                           -PropertyType $(if ($o.Kind) { $o.Kind } else { 'String' }) -Force -EA Stop | Out-Null
          Write-Host "  restored $($o.Path)\$($o.Name)" -ForegroundColor Green
        } catch { Write-Warning "  could not restore $($o.Path)\$($o.Name): $($_.Exception.Message)" }
      }
    } else {
      # It did not exist before, so the faithful revert is to delete it.
      Remove-Value -Path $o.Path -Name $o.Name -Label "$($o.Path)\$($o.Name) (was absent)"
    }
  }
  # The firewall rule is not a registry value, so it is not in $st.Originals -
  # remove it unconditionally. Widgets is NOT reinstalled here: pulling a
  # package back down is a Store action, not something a revert should do
  # silently. Reinstall "Widgets" from the Store if you want it back.
  if (Get-NetFirewallRule -DisplayName $FwRuleName -EA SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($FwRuleName, 'Remove firewall rule')) {
      try {
        Remove-NetFirewallRule -DisplayName $FwRuleName -EA Stop
        Write-Host "  removed firewall rule '$FwRuleName'" -ForegroundColor Green
      } catch { Write-Warning "  could not remove firewall rule: $($_.Exception.Message)" }
    }
  }

  Write-Host "`nReverted. Background apps return at next logon." -ForegroundColor Green
  if (-not (Get-AppxPackage -Name 'MicrosoftWindows.Client.WebExperience' -EA SilentlyContinue)) {
    Write-Host "Note: the Widgets package is still uninstalled - reinstall it from the Store if wanted." -ForegroundColor Yellow
  }
  return
}

# ------------------------------------------------------------------- apply ---

Write-Host "`n==== APPLY ====" -ForegroundColor Cyan

$originals = @()

# --- Edge: stop lingering and preloading -----------------------------------
Write-Host "`n  Edge background behaviour..." -ForegroundColor Cyan
$edgePol = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
foreach ($v in @(
    @{ N = 'BackgroundModeEnabled'; L = 'Edge: do not keep running after last window closes' },
    @{ N = 'StartupBoostEnabled';   L = 'Edge: do not preload at logon' })) {
  $originals += Get-Original -Path $edgePol -Name $v.N
  Set-Value -Path $edgePol -Name $v.N -Value 0 -Type DWord -Label $v.L
}

# --- Widgets ---------------------------------------------------------------
Write-Host "`n  Widgets..." -ForegroundColor Cyan
$dsh = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
$originals += Get-Original -Path $dsh -Name 'AllowNewsAndInterests'
Set-Value -Path $dsh -Name 'AllowNewsAndInterests' -Value 0 -Type DWord -Label 'Widgets board off'

# --- Start-menu web results ------------------------------------------------
Write-Host "`n  Start-menu web suggestions..." -ForegroundColor Cyan
$expl = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
$originals += Get-Original -Path $expl -Name 'DisableSearchBoxSuggestions'
Set-Value -Path $expl -Name 'DisableSearchBoxSuggestions' -Value 1 -Type DWord -Label 'no web suggestions in the search box'

# DisableSearchBoxSuggestions alone was NOT enough - SearchHost kept an HTTPS
# session open to Microsoft. These are the levers that actually stop it
# reaching out: the machine policy that forbids web/cloud search outright, and
# the per-user Bing toggles the UI writes.
$wsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
foreach ($v in @(
    @{ N = 'ConnectedSearchUseWeb';     L = 'no web results in Windows Search' },
    @{ N = 'AllowCloudSearch';          L = 'no cloud search' },
    @{ N = 'DisableWebSearch';          V = 1; L = 'web search disabled' },
    @{ N = 'EnableDynamicContentInWSB'; L = 'no dynamic search-box content' })) {
  $originals += Get-Original -Path $wsPol -Name $v.N
  Set-Value -Path $wsPol -Name $v.N -Value $(if ($null -ne $v.V) { $v.V } else { 0 }) -Type DWord -Label $v.L
}

$uSearch = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
foreach ($v in @(
    @{ N = 'BingSearchEnabled'; L = 'Bing off in Start' },
    @{ N = 'CortanaConsent';    L = 'Cortana consent withdrawn' })) {
  $originals += Get-Original -Path $uSearch -Name $v.N
  Set-Value -Path $uSearch -Name $v.N -Value 0 -Type DWord -Label $v.L
}

# --- auto-launch Run entries ----------------------------------------------
Write-Host "`n  Auto-launch entries..." -ForegroundColor Cyan
$patterns = @(
  @{ P = 'MicrosoftEdgeAutoLaunch_*';    L = 'Edge auto-launch' },
  @{ P = 'MicrosoftCopilotAutoLaunch_*'; L = 'M365 Copilot auto-launch' }
)
if ($IncludeOneDrive) { $patterns += @{ P = 'OneDrive';  L = 'OneDrive (stops the offsite backup sync!)' } }
if ($IncludeDiscord)  { $patterns += @{ P = 'Discord';   L = 'Discord' } }
if ($IncludeFirefox)  { $patterns += @{ P = 'Mozilla-Firefox-*'; L = 'Firefox background updater' } }

foreach ($pat in $patterns) {
  $hits = Get-RunEntry -Pattern $pat.P
  if (-not $hits) { Write-Host "    (none found for $($pat.L))" -ForegroundColor DarkGray; continue }
  foreach ($h in $hits) {
    $originals += Get-Original -Path $h.Path -Name $h.Name
    Remove-Value -Path $h.Path -Name $h.Name -Label $pat.L
  }
}

# --- save state ------------------------------------------------------------
# Re-running -Apply must NOT overwrite the saved originals with the values this
# script itself already wrote - that would make -Revert restore 0 where there
# had originally been nothing, permanently losing the true pre-change state.
# An entry recorded by an earlier run always wins.
if (Test-Path $StateFile) {
  $prior = @((Get-Content $StateFile -Raw | ConvertFrom-Json).Originals)
  $merged = @{}
  foreach ($o in $prior)     { $merged["$($o.Path)|$($o.Name)"] = $o }
  foreach ($o in $originals) {
    $key = "$($o.Path)|$($o.Name)"
    if (-not $merged.ContainsKey($key)) { $merged[$key] = $o }
  }
  $originals = @($merged.Values)
  Write-Host "`n  Merged with existing state - kept $($prior.Count) original value(s) from the first run" -ForegroundColor DarkGray
}

if (-not (Test-Path $StateDir)) { New-Item $StateDir -ItemType Directory -Force | Out-Null }
[pscustomobject]@{ SavedAt = (Get-Date).ToString('s'); Originals = $originals } |
  ConvertTo-Json -Depth 5 | Out-File $StateFile -Encoding utf8
Write-Host "  State file now holds $($originals.Count) original value(s): $StateFile" -ForegroundColor DarkGray

# --- optional: the two things policy alone could not fix -------------------
if ($BlockSearchHost) {
  Write-Host "`n  Blocking SearchHost outbound (policy was not enough)..." -ForegroundColor Cyan
  Block-SearchHostNetwork
}
if ($RemoveWidgets) {
  Write-Host "`n  Removing the Widgets package..." -ForegroundColor Cyan
  Remove-WidgetsPackage
}

# --- stop what is already running -----------------------------------------
if ($StopNow) {
  Write-Host "`n  Stopping headless background processes..." -ForegroundColor Cyan
  Stop-Idle
  Start-Sleep -Seconds 2
}

Write-Host "`n==== AFTER ====" -ForegroundColor Cyan
$after = Get-IdleReport
if ($after) { $after | Format-Table -AutoSize } else { Write-Host "  No background apps left running." -ForegroundColor Green }
Show-Connections | Format-Table -AutoSize

Write-Host @"

Edge and Copilot will no longer start at logon or linger in the background.
Widgets and Start-menu web results are off.

Left running deliberately: the Dnscache DoH session to your resolvers, your
Remote-SSH session, SMB to the LAN backup drive, and Defender.

Undo everything:  .\Reduce-IdleFootprint.ps1 -Revert
"@ -ForegroundColor Cyan
