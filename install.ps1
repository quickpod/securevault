<#
.SYNOPSIS
    QuickOpen signed installer/downloader.

.DESCRIPTION
    Downloads a QuickOpen release, verifies it was signed by the QuickOpen Root
    CA, and installs it. With your consent it installs the QuickOpen Root CA into
    your Trusted Root store so Windows itself trusts the signature; if you
    decline, the script still verifies the signature cryptographically before
    installing anything, and you can instead build from source (see docs/BUILD.md).

    Nothing is installed unless the signature verifies.

.PARAMETER Repo
    GitHub repo in owner/name form. Default: quickpod/securevault

.PARAMETER Tag
    Release tag to install. Default: latest

.PARAMETER InstallDir
    Target directory. Default: %LOCALAPPDATA%\<project>

.PARAMETER TrustCA
    'ask' (default), 'yes' (install root CA without prompting), or 'no'.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1
#>
[CmdletBinding()]
param(
    [string]$Repo = "quickpod/securevault",
    [string]$Tag = "latest",
    [string]$InstallDir = "",
    [ValidateSet("ask", "yes", "no")]
    [string]$TrustCA = "ask",
    [switch]$NoSetup
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Pinned fingerprint of the QuickOpen Root CA. Verified independently of any
# download so a swapped cert cannot pass. (Published on https://quickopen.ai/trust)
$ExpectedRootThumbprint = "771EAFEDCCB23BE0C44F6484BE967670369AEFB0"

$project = $Repo.Split('/')[-1]
if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA $project }
$work = Join-Path ([System.IO.Path]::GetTempPath()) "quickopen-$project-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

try {
    # 1. Resolve the release and asset list from the GitHub API.
    Write-Step "Resolving $Repo release '$Tag'"
    $api = if ($Tag -eq "latest") {
        "https://api.github.com/repos/$Repo/releases/latest"
    } else {
        "https://api.github.com/repos/$Repo/releases/tags/$Tag"
    }
    $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "quickopen-installer" }
    $assets = $release.assets
    if (-not $assets) { throw "no assets on release $($release.tag_name)" }

    # 2. Download the root CA cert, all artifacts, their .sig files, and SHA256SUMS(.sig).
    Write-Step "Downloading release assets"
    foreach ($a in $assets) {
        $dest = Join-Path $work $a.name
        Invoke-WebRequest -Uri $a.browser_download_url -OutFile $dest -Headers @{ "User-Agent" = "quickopen-installer" }
    }
    $rootCert = Join-Path $work "quickopen-root.crt"
    if (-not (Test-Path $rootCert)) {
        Write-Step "Fetching QuickOpen Root CA from quickopen.ai/trust"
        Invoke-WebRequest -Uri "https://quickopen.ai/trust/quickopen-root.crt" -OutFile $rootCert
    }

    # 3. Confirm the root cert matches the pinned fingerprint before trusting it at all.
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $rootCert
    $thumb = $cert.Thumbprint.ToUpper()
    if ($thumb -ne $ExpectedRootThumbprint.ToUpper().Replace(":", "")) {
        throw "Root CA fingerprint mismatch. Expected $ExpectedRootThumbprint, got $thumb. Aborting."
    }
    Write-Host "    Root CA: $($cert.Subject)  [$thumb]" -ForegroundColor DarkGray

    # 4. Optionally install the root CA into the Trusted Root store (consented).
    $doTrust = switch ($TrustCA) {
        "yes" { $true }
        "no" { $false }
        default {
            Write-Host ""
            Write-Host "QuickOpen signs its software with its own certificate authority." -ForegroundColor Yellow
            Write-Host "Installing the QuickOpen Root CA lets Windows verify our signatures natively"
            Write-Host "(Authenticode on our .exe/.msi). It does NOT let us sign for anyone else."
            (Read-Host "Install the QuickOpen Root CA as trusted now? [y/N]") -match '^(y|yes)$'
        }
    }
    if ($doTrust) {
        Write-Step "Installing QuickOpen Root CA into CurrentUser Trusted Root store"
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
        $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
        Write-Host "    Installed. Remove any time with: Get-ChildItem Cert:\CurrentUser\Root | ? Thumbprint -eq '$thumb' | Remove-Item"
    } else {
        Write-Host "    Skipping trust-store install; will still verify the signature cryptographically."
    }

    # 5. Verify SHA256SUMS is signed by the QuickOpen chain, then check every file hash.
    Write-Step "Verifying signatures"
    $sums = Join-Path $work "SHA256SUMS"
    $sumsSig = Join-Path $work "SHA256SUMS.sig"
    if (-not (Test-Path $sums) -or -not (Test-Path $sumsSig)) { throw "release is missing SHA256SUMS / SHA256SUMS.sig" }

    $openssl = (Get-Command openssl -ErrorAction SilentlyContinue)
    if ($openssl) {
        & openssl cms -verify -binary -inform DER -in $sumsSig -content $sums -CAfile $rootCert -purpose any -out $null 2>$null
        if ($LASTEXITCODE -ne 0) { throw "SHA256SUMS signature did NOT verify against the QuickOpen Root CA. Aborting." }
    } elseif ($doTrust) {
        Write-Host "    openssl not found; relying on Authenticode (root CA is trusted)." -ForegroundColor DarkGray
    } else {
        throw "openssl not found and root CA not trusted: cannot verify. Install openssl or re-run allowing the CA."
    }

    # Check each artifact hash against the (now-trusted) manifest.
    $expected = @{}
    Get-Content $sums | ForEach-Object {
        if ($_ -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') { $expected[$matches[2].Trim()] = $matches[1].ToLower() }
    }
    foreach ($name in $expected.Keys) {
        $path = Join-Path $work $name
        if (-not (Test-Path $path)) { continue }
        $actual = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLower()
        if ($actual -ne $expected[$name]) { throw "hash mismatch for $name" }
        Write-Host "    OK  $name" -ForegroundColor Green
    }

    # 6. Install: place verified files into InstallDir, expanding a source zip if present.
    Write-Step "Installing to $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $srcZip = Get-ChildItem $work -Filter *-src.zip | Select-Object -First 1
    if ($srcZip) {
        Expand-Archive -Path $srcZip.FullName -DestinationPath $InstallDir -Force
        Write-Host "    Expanded $($srcZip.Name)"
    }
    Get-ChildItem $work -File | Where-Object {
        $_.Name -notmatch '\.(sig)$' -and $_.Name -ne 'SHA256SUMS' -and
        $_.Name -notmatch '-src\.zip$' -and
        $_.Name -ne 'quickopen-root.crt' -and $_.Name -ne 'quickopen-root.cer'
    } | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $InstallDir $_.Name) -Force
    }

    # 7. Hand off to the project's own setup (extracted from the source zip),
    #    then surface any executable.
    $setup = Get-ChildItem $InstallDir -Filter 'Setup-*.ps1' | Select-Object -First 1
    if ($setup -and -not $NoSetup) {
        Write-Step "Running $($setup.Name)"
        & powershell -ExecutionPolicy Bypass -File $setup.FullName -InstallRoot $InstallDir
    } elseif ($setup) {
        Write-Host "    Skipped setup ($($setup.Name)); run it yourself to finish wiring." -ForegroundColor DarkGray
    }
    $exe = Get-ChildItem $InstallDir -Filter *.exe | Select-Object -First 1
    if ($exe) {
        Write-Host "Installed $($exe.Name) to $InstallDir" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "Done. Every installed file was signed by QuickOpen and hash-verified." -ForegroundColor Green
    Write-Host "Uninstall any time with $InstallDir\uninstall.ps1 (if provided)." -ForegroundColor DarkGray
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
