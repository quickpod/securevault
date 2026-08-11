<#
    New-IosDohProfile.ps1  -  build an iOS configuration profile that points the
                              iPhone at your own DoH resolver, system-wide.

    No Mac, no Xcode, no App Store. A .mobileconfig is plain XML; iOS installs
    it from Mail, Safari, AirDrop or Files. This runs unelevated on Windows.

    WHY A PROFILE AND NOT AN APP
    On iOS the 'com.apple.dnsSettings.managed' payload sets encrypted DNS for
    the whole device - every app, not just a browser - and it works on an
    UNSUPERVISED phone. An app using NEDNSSettingsManager does the same thing
    with more code and an entitlement. Start here.

    HOW THIS DIFFERS FROM THE WINDOWS SETUP - READ THIS
    Set-PrivateDoh.ps1 lists two of your servers and adds a watchdog that swaps
    in 1.1.1.1/8.8.8.8 if both go dark. iOS CANNOT do that. A DNS payload
    carries exactly ONE ServerURL, because ServerAddresses are alternate IPs
    for that one hostname and certificate - and your two endpoints are
    different hosts with different tokens, so they cannot be pooled.

    Consequence: if the chosen resolver goes down, the iPhone stops resolving
    until you turn the profile off. There is no automatic fallback and no
    watchdog. That is the escape hatch, and it is manual:

        Settings > General > VPN, DNS & Device Management > (this profile)
        or  Settings > Wi-Fi > (i) > DNS  to override for one network

    Same trade as the laptop, minus the safety net. Know where that switch is
    BEFORE you travel. Captive portals are the case you will hit: a hotel
    splash page cannot be reached until DNS works, so expect to toggle off,
    sign in, toggle back on.

    TOKENS - THIS OUTPUT IS A CREDENTIAL
    Your endpoint URLs authenticate with a token in the URL path. The
    generated .mobileconfig therefore CONTAINS that token in cleartext. It is
    written to C:\SecureVault by default, deliberately OUTSIDE any folder that
    is synced to the cloud or backed up off-machine. Do not move it into such a
    folder, and do not mail it to yourself through an account you do not control.
    Delete it from the phone's Files/Mail after installing.

    PINNING
    By default the resolver hostname is resolved now and the IPs are pinned
    into ServerAddresses, so the phone never leaks a bootstrap lookup for your
    resolver's hostname to a hotel DNS server. If those IPs renumber, DNS
    breaks and you re-run this and reinstall - the iOS equivalent of -Refresh.
    Use -NoPin to let iOS bootstrap via the local resolver instead.

    USAGE
      .\New-IosDohProfile.ps1                    # primary endpoint, pinned
      .\New-IosDohProfile.ps1 -Use Secondary     # the other endpoint
      .\New-IosDohProfile.ps1 -NoPin
      .\New-IosDohProfile.ps1 -OutFile C:\Temp\doh.mobileconfig
#>
[CmdletBinding()]
param(
    [ValidateSet('Primary','Secondary')] [string] $Use = 'Primary',
    [string] $DohFile = 'S:\doh',
    [string] $OutFile,
    [switch] $NoPin
)

$ErrorActionPreference = 'Stop'

# ---- endpoint list: parsed, never hardcoded (same rule as Set-PrivateDoh) ---
if (-not (Test-Path -LiteralPath $DohFile)) { throw "Endpoint file not found: $DohFile" }
$urls = @(Get-Content -LiteralPath $DohFile | Where-Object { $_ -match '^\s*https://\S+\s*$' } |
          ForEach-Object { $_.Trim() })
if ($urls.Count -lt 1) { throw "No https:// endpoint URLs found in '$DohFile'." }

$index = if ($Use -eq 'Primary') { 0 } else { 1 }
if ($index -ge $urls.Count) { throw "'$Use' requested but only $($urls.Count) endpoint(s) in '$DohFile'." }
$serverUrl = $urls[$index]
$host_     = ([uri]$serverUrl).Host

# ---- pin the IPs so no bootstrap lookup leaks on an untrusted network -------
$addresses = @()
if (-not $NoPin) {
    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($host_) |
                       Where-Object { $_.AddressFamily -in 'InterNetwork','InterNetworkV6' } |
                       ForEach-Object { $_.IPAddressToString } | Sort-Object -Unique)
    } catch {
        throw "Could not resolve '$host_' to pin its IPs. Re-run with -NoPin, or fix DNS first. ($($_.Exception.Message))"
    }
    if ($addresses.Count -eq 0) { throw "'$host_' resolved to no usable addresses. Use -NoPin." }
}

if (-not $OutFile) {
    if (-not (Test-Path 'C:\SecureVault')) { $null = New-Item -ItemType Directory -Path 'C:\SecureVault' }
    $OutFile = "C:\SecureVault\ios-doh-$($host_ -replace '[^\w.-]','_').mobileconfig"
}

function Esc([string] $s) {
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
}

$payloadUuid = [guid]::NewGuid().ToString().ToUpper()
$topUuid     = [guid]::NewGuid().ToString().ToUpper()
$addrXml     = if ($addresses.Count) {
    "        <key>ServerAddresses</key>`r`n        <array>`r`n" +
    (($addresses | ForEach-Object { "          <string>$(Esc $_)</string>" }) -join "`r`n") +
    "`r`n        </array>`r`n"
} else { '' }

$xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key>            <string>Configuration</string>
  <key>PayloadVersion</key>         <integer>1</integer>
  <key>PayloadIdentifier</key>      <string>vault.securevault.doh</string>
  <key>PayloadUUID</key>            <string>$topUuid</string>
  <key>PayloadDisplayName</key>     <string>SecureVault Encrypted DNS</string>
  <key>PayloadDescription</key>     <string>Routes all DNS on this device over HTTPS to $(Esc $host_). Remove this profile to restore the network's DNS.</string>
  <key>PayloadOrganization</key>    <string>SecureVault</string>
  <key>PayloadRemovalDisallowed</key> <false/>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>        <string>com.apple.dnsSettings.managed</string>
      <key>PayloadVersion</key>     <integer>1</integer>
      <key>PayloadIdentifier</key>  <string>vault.securevault.doh.dns</string>
      <key>PayloadUUID</key>        <string>$payloadUuid</string>
      <key>PayloadDisplayName</key> <string>DNS over HTTPS</string>
      <key>ProhibitDisablement</key> <false/>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>      <string>HTTPS</string>
        <key>ServerURL</key>        <string>$(Esc $serverUrl)</string>
$addrXml      </dict>
    </dict>
  </array>
</dict>
</plist>
"@

[System.IO.File]::WriteAllText($OutFile, $xml, (New-Object System.Text.UTF8Encoding($false)))

''
"Profile written : $OutFile"
"Endpoint        : $Use  ->  https://$host_/<token redacted>"
if ($addresses.Count) { "Pinned addresses: $($addresses -join ', ')" }
else                  { 'Pinned addresses: none (-NoPin) - iOS will bootstrap via the local resolver' }
''
'THIS FILE CONTAINS YOUR BEARER TOKEN IN CLEARTEXT.'
'Keep it out of any cloud-synced folder. Delete it from the phone after installing.'
''
'To install: AirDrop or copy to the iPhone, open it, then'
'  Settings > General > VPN, DNS & Device Management > Downloaded Profile > Install'
'To verify:  browse to https://1.1.1.1/help on the phone - "Using DNS over HTTPS" should be Yes,'
'            or query whoami.akamai.net and confirm the egress is your resolver.'
'To disable in a hurry (captive portal): same Settings pane, toggle or remove the profile.'
''
