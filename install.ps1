#!/usr/bin/env pwsh

# Beam-rs installer for Windows
# Downloads latest binary from: https://github.com/andrewtheguy/beam-rs/releases
#
# Invocation is now argument-parsed only (compat-breaking): flags are read from
# $args or $env:BEAM_INSTALL_ARGS. Param binding is removed.

# Defaults (will be overwritten by fallback arg parser)
$ReleaseTag   = $null
$Admin        = $false
$PreRelease   = $false
$DownloadOnly = $false

$ErrorActionPreference = "Stop"

$REPO_OWNER = "andrewtheguy"
$REPO_NAME = "beam-rs"

# Allow passing flags when the script is piped into Invoke-Expression (iex) where
# normal PowerShell parameter binding is unavailable. Users can set
# $env:BEAM_INSTALL_ARGS to a PowerShell-style argument string, e.g.:
#   $env:BEAM_INSTALL_ARGS='-PreRelease'; irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex
# This keeps the single-line install experience while still supporting flags.

# Function to print colored messages
function Print-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Print-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Print-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Fetch the latest stable release tag (non-prerelease)
function Get-LatestReleaseTag {
    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest"
    
    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Method Get
    }
    catch {
        Print-Error "Failed to fetch latest release from GitHub: $_"
        exit 1
    }

    if (-not $release.tag_name) {
        Print-Error "Could not find a latest release on GitHub"
        exit 1
    }

    return $release.tag_name
}

# Fetch the latest prerelease tag
function Get-LatestPrereleaseTag {
    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases?per_page=30"

    try {
        $releases = Invoke-RestMethod -Uri $apiUrl -Method Get
    }
    catch {
        Print-Error "Failed to fetch releases from GitHub: $_"
        exit 1
    }

    $latestPrerelease = $releases |
        Where-Object { $_.prerelease -eq $true } |
        Select-Object -First 1 -ExpandProperty tag_name

    if (-not $latestPrerelease) {
        Print-Error "Could not find any prerelease on GitHub"
        exit 1
    }

    return $latestPrerelease
}

# Fetch full release info (including asset checksums) from GitHub API
function Get-ReleaseInfo {
    param([string]$Tag)
    
    $apiUrl = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/tags/$Tag"
    
    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Method Get
        return $release
    }
    catch {
        Print-Warn "Could not fetch release info: $_"
        return $null
    }
}

# Extract SHA-256 checksum from release JSON for a specific binary
function Get-ExpectedChecksum {
    param(
        [object]$ReleaseInfo,
        [string]$BinaryName
    )

    if (-not $ReleaseInfo -or -not $ReleaseInfo.assets) {
        return $null
    }

    # Find the asset matching the binary name
    $asset = $ReleaseInfo.assets | Where-Object { $_.name -eq $BinaryName } | Select-Object -First 1
    
    if (-not $asset) {
        return $null
    }

    # Extract sha256 hash from digest field
    if ($asset.digest -match 'sha256:([a-f0-9]+)') {
        return $matches[1]
    }

    return $null
}

# Compute SHA-256 checksum of a file
function Get-FileChecksum {
    param([string]$FilePath)
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash.ToLower()
    }
    catch {
        Print-Error "Failed to compute checksum: $_"
        return $null
    }
}

# Verify file checksum against expected value
function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedChecksum
    )

    Print-Info "Verifying checksum..."
    $actualChecksum = Get-FileChecksum -FilePath $FilePath

    if (-not $actualChecksum) {
        return $false
    }

    if ($ExpectedChecksum -eq $actualChecksum) {
        $shortHash = $actualChecksum.Substring(0, 16)
        Print-Info "Checksum verified: $shortHash..."
        return $true
    }
    else {
        Print-Error "Checksum verification FAILED!"
        Print-Error "Expected: $ExpectedChecksum"
        Print-Error "Actual:   $actualChecksum"
        return $false
    }
}

# Detect architecture
function Get-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    
    if ($arch -ne "AMD64") {
        Print-Error "Unsupported architecture: $arch"
        Print-Error "Only AMD64 (x86_64) is supported for Windows"
        exit 1
    }
    
    return "amd64"
}

# Get binary name based on architecture
function Get-BinaryName {
    param([string]$Arch)

    if ($Arch -ne "amd64") {
        Print-Error "Unsupported architecture: $Arch"
        Print-Error "Only amd64 is supported for Windows"
        exit 1
    }

    return "beam-rs-windows-amd64.exe"
}

function Get-InstallName {
    return "beam-rs.exe"
}

# Parse argument strings (e.g., from environment variables) using PowerShell's tokenizer
function Parse-ArgString {
    param([string]$ArgString)

    if ([string]::IsNullOrWhiteSpace($ArgString)) {
        return @()
    }

    $errors = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($ArgString, [ref]$errors)

    if ($errors -and $errors.Count -gt 0) {
        Print-Warn "Could not parse BEAM_INSTALL_ARGS: $($errors[0].Message)"
        return @()
    }

    return $tokens |
        Where-Object { $_.Type -in @('CommandArgument', 'CommandParameter', 'String', 'Number') } |
        ForEach-Object { $_.Content }
}

# Bind arguments when invoked via Invoke-Expression (iex) where parameter binding is unavailable
function Apply-FallbackArgs {
    param([string[]]$ArgList)

    if (-not $ArgList -or $ArgList.Count -eq 0) {
        return
    }

    $unhandled = @()

    foreach ($arg in $ArgList) {
        if (-not $arg) { continue }

        $argLower = $arg.ToLowerInvariant()
        switch ($argLower) {
            '-admin' { $script:Admin = $true; continue }
            '/admin' { $script:Admin = $true; continue }
            '-prerelease' { $script:PreRelease = $true; continue }
            '/prerelease' { $script:PreRelease = $true; continue }
            '-downloadonly' { $script:DownloadOnly = $true; continue }
            '/downloadonly' { $script:DownloadOnly = $true; continue }
            '-h' { Show-Usage; exit 0 }
            '/h' { Show-Usage; exit 0 }
            '--help' { Show-Usage; exit 0 }
            '-?' { Show-Usage; exit 0 }
            '/?' { Show-Usage; exit 0 }
            default {
                if (-not $script:ReleaseTag) {
                    $script:ReleaseTag = $arg
                }
                else {
                    $unhandled += $arg
                }
            }
        }
    }

    if ($unhandled.Count -gt 0) {
        Print-Warn "Ignoring unrecognized fallback arguments: $($unhandled -join ' ')"
    }
}

# Download binary and verify checksum
function Download-Binary {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$ExpectedChecksum
    )

    Print-Info "Downloading from $Url"

    # Download the binary
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
    }
    catch {
        Print-Error "Failed to download binary: $_"
        exit 1
    }

    # Verify checksum
    if (-not $ExpectedChecksum) {
        Print-Error "No checksum available. Aborting."
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
    if (-not (Test-Checksum -FilePath $OutputPath -ExpectedChecksum $ExpectedChecksum)) {
        Print-Error "Binary integrity check failed. Aborting."
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# Download only - save to current directory
function Download-Only {
    param(
        [string]$BaseUrl,
        [string]$BinaryName,
        [string]$ExpectedChecksum
    )

    $url = "$BaseUrl/$BinaryName"
    $outputFile = Join-Path (Get-Location) $BinaryName

    Download-Binary -Url $url -OutputPath $outputFile -ExpectedChecksum $ExpectedChecksum

    # Test the binary
    Print-Info "Testing downloaded binary..."
    try {
        $versionInfo = & $outputFile --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Binary returned non-zero exit code"
        }
        Print-Info "Binary test successful: $versionInfo"
    }
    catch {
        Print-Error "Binary test failed. The downloaded file may be corrupted or incompatible."
        Print-Error "Output: $_"
        Remove-Item -Path $outputFile -Force -ErrorAction SilentlyContinue
        exit 1
    }

    Print-Info "Binary saved to: $outputFile"
}

# Download binary to temporary location, test it, and install
function Install-Binary {
    param(
        [string]$BaseUrl,
        [string]$BinaryName,
        [string]$ExpectedChecksum
    )

    $url = "$BaseUrl/$BinaryName"
    $tempDir = Join-Path $env:TEMP "beam-rs-install-$(Get-Random)"
    $tempBinary = Join-Path $tempDir $BinaryName
    $installDir = Join-Path $env:LOCALAPPDATA "Programs\beam-rs"
    $installName = Get-InstallName
    $finalPath = Join-Path $installDir $installName

    try {
        # Create temp directory
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        Download-Binary -Url $url -OutputPath $tempBinary -ExpectedChecksum $ExpectedChecksum

        # Test the binary
        Print-Info "Testing downloaded binary..."
        try {
            $versionInfo = & $tempBinary --version 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Binary returned non-zero exit code"
            }
            Print-Info "Binary test successful: $versionInfo"
        }
        catch {
            Print-Error "Binary test failed. The downloaded file may be corrupted or incompatible."
            Print-Error "Output: $_"
            exit 1
        }

        # Create target directory if it doesn't exist
        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        # Move the tested binary to final location
        try {
            Move-Item -Path $tempBinary -Destination $finalPath -Force
        }
        catch {
            Print-Error "Failed to move binary to final location: $_"
            exit 1
        }

        Print-Info "Binary installed successfully to $finalPath"

        # Add to PATH if not already there
        $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$installDir*") {
            Print-Warn "$installDir is not in your PATH"
            Print-Warn "Adding to user PATH..."
            
            try {
                $newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
                [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
                Print-Info "Added to PATH. You may need to restart your terminal for changes to take effect."
            }
            catch {
                Print-Warn "Failed to add to PATH automatically. Please add manually:"
                Print-Warn "$installDir"
            }
        }
        else {
            Print-Info "$installDir is already in your PATH"
        }
    }
    finally {
        # Clean up temp directory
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Display usage information
function Show-Usage {
    Write-Host @"
Usage: .\install.ps1 [OPTIONS] [RELEASE_TAG]

Download and install beam-rs binary

Options:
  -DownloadOnly  Download binary to current directory without installing
  -PreRelease    Use latest prerelease instead of latest stable release
  -Admin         Allow installation with administrator privileges (not recommended)
  -h, --help     Show this help message

Arguments:
    RELEASE_TAG    GitHub release tag to download (default: latest)

Environment variables:
  `$env:RELEASE_TAG    Alternative way to specify release tag
    `$env:BEAM_INSTALL_ARGS  Fallback flags for iex one-liners (e.g. "-PreRelease")

Examples:
    .\install.ps1                              # Install latest beam-rs (args-only parser)
    .\install.ps1 20251210172710               # Install specific release
    .\install.ps1 -PreRelease                  # Install latest prerelease
    .\install.ps1 -DownloadOnly                # Download latest to current directory
    .\install.ps1 -DownloadOnly 20251210172710 # Download specific release
    .\install.ps1 -Admin                       # Allow admin installation (not recommended)
    `$env:RELEASE_TAG='latest'; .\install.ps1  # Use environment variable
    `$env:BEAM_INSTALL_ARGS='-PreRelease'; irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex

Supported platforms: Windows (amd64)

Note: Installation as administrator is not recommended. Use -Admin flag to override.
"@
}

# Check if running with administrator privileges
function Test-AdminPrivileges {
    param([bool]$AllowAdmin)
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        if (-not $AllowAdmin) {
            Print-Error "Installation as administrator is not allowed without explicit override."
            Print-Error "Running as administrator can cause permission issues and is not recommended."
            Print-Error ""
            Print-Error "To proceed anyway, run with the -Admin flag:"
            Print-Error "  .\install.ps1 -Admin"
            Print-Error ""
            Print-Error "Recommended: Run this installer as a regular user instead."
            exit 1
        }
        else {
            Print-Warn "Running as administrator with explicit override (-Admin flag)."
            Print-Warn "This is not recommended and may cause permission issues."
        }
    }
}

# Main installation function
function Start-Installation {
    param(
        [string]$Tag,
        [bool]$DownloadOnly
    )

    if ($DownloadOnly) {
        Print-Info "Beam-rs downloader"
    }
    else {
        Print-Info "Beam-rs installer"
    }
    Print-Info "Release: $Tag"
    Print-Info "Repository: $REPO_OWNER/$REPO_NAME"

    $arch = Get-Architecture
    $binaryName = Get-BinaryName -Arch $arch

    Print-Info "Platform detected: windows-$arch"
    Print-Info "Binary name: $binaryName"

    $baseUrl = "https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$Tag"

    # Fetch release info for checksum verification
    Print-Info "Fetching release information..."
    $releaseInfo = Get-ReleaseInfo -Tag $Tag

    if (-not $releaseInfo) {
        Print-Error "Could not fetch release info from GitHub. Cannot verify binary integrity."
        exit 1
    }

    $expectedChecksum = Get-ExpectedChecksum -ReleaseInfo $releaseInfo -BinaryName $binaryName
    if (-not $expectedChecksum) {
        Print-Error "No checksum found for $binaryName in release. Cannot verify binary integrity."
        exit 1
    }
    $shortHash = $expectedChecksum.Substring(0, 16)
    Print-Info "Expected checksum: $shortHash..."

    if ($DownloadOnly) {
        Download-Only -BaseUrl $baseUrl -BinaryName $binaryName -ExpectedChecksum $expectedChecksum
        Print-Info "Download completed successfully!"
    }
    else {
        Install-Binary -BaseUrl $baseUrl -BinaryName $binaryName -ExpectedChecksum $expectedChecksum
        Print-Info "Installation completed successfully!"
        $installName = Get-InstallName
        Print-Info "You can now run '$installName' from your terminal."
    }
}

# Main execution
function Main {
    # Capture arguments from $args and env for both iex and direct runs
        $fallbackArgs = @()
        if ($args -and $args.Count -gt 0) {
            $fallbackArgs += $args
        }
        if ($env:BEAM_INSTALL_ARGS) {
            $fallbackArgs += (Parse-ArgString -ArgString $env:BEAM_INSTALL_ARGS)
        }
        Apply-FallbackArgs -ArgList $fallbackArgs

        # Extra guard: honor env flags even if tokenization failed
        $envArgs = $env:BEAM_INSTALL_ARGS
        if ($envArgs) {
            if (-not $PreRelease -and $envArgs -match '(?i)(^|\s)--?prerelease(\s|$)') { $PreRelease = $true }
            if (-not $DownloadOnly -and $envArgs -match '(?i)(^|\s)--?downloadonly(\s|$)') { $DownloadOnly = $true }
            if (-not $Admin -and $envArgs -match '(?i)(^|\s)--?admin(\s|$)') { $Admin = $true }
            if (-not $ReleaseTag -and $envArgs -match '^(\s*[^-][^\s]+)') {
                $ReleaseTag = $matches[1].Trim()
            }
        }

    # Handle help flags - check both parameter and ReleaseTag value
    if ($args -contains "--help" -or $args -contains "-h" -or $args -contains "-?" -or $args -contains "/?" -or $args -contains "/h" -or
        $ReleaseTag -eq "--help" -or $ReleaseTag -eq "-h" -or $ReleaseTag -eq "-?" -or $ReleaseTag -eq "/?" -or $ReleaseTag -eq "/h") {
        Show-Usage
        exit 0
    }

    if ($DownloadOnly) {
        Print-Info "Starting Beam-rs download..."
    }
    else {
        Print-Info "Starting Beam-rs installation..."
    }

    # Determine release tag
    $tag = $ReleaseTag
    if (-not $tag) {
        $tag = $env:RELEASE_TAG
    }
    if (-not $tag) {
        if ($PreRelease) {
            Print-Info "Fetching latest prerelease tag from GitHub..."
            $tag = Get-LatestPrereleaseTag
        }
        else {
            Print-Info "Fetching latest release tag from GitHub..."
            $tag = Get-LatestReleaseTag
        }
    }

    if (-not $DownloadOnly) {
        Test-AdminPrivileges -AllowAdmin:$Admin
    }
    
    Start-Installation -Tag $tag -DownloadOnly:$DownloadOnly
}

# Run main function and clean up fallback args
try {
    Main
}
finally {
    # Clean up the fallback args variable to avoid persistence across sessions
    if (Test-Path env:BEAM_INSTALL_ARGS) {
        Remove-Item env:BEAM_INSTALL_ARGS -ErrorAction SilentlyContinue
    }
}
