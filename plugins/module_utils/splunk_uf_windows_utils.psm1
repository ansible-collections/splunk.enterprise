# Copyright: (c) 2025, splunk.enterprise contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# Shared utility functions for Splunk Universal Forwarder Windows modules

# Supported Windows Server versions and their build numbers
$script:SupportedWindowsServerBuilds = @{
    17763 = "Windows Server 2019"
    20348 = "Windows Server 2022"
    26100 = "Windows Server 2025"
}

# Validate that the module is running on a supported Windows Server version.
# Returns a hashtable with 'is_supported', 'os_name', 'os_build', and 'error_message' keys.
function Test-SupportedWindowsServer {
    $result = @{
        is_supported = $false
        os_name = $null
        os_build = $null
        error_message = $null
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $result.os_name = $os.Caption
        $result.os_build = [int]$os.BuildNumber

        # Check if the build number is supported (Windows Server 2019, 2022, 2025)
        if ($script:SupportedWindowsServerBuilds.ContainsKey($result.os_build)) {
            $result.is_supported = $true
            return $result
        }

        # Build number not in our supported list
        $supportedVersions = ($script:SupportedWindowsServerBuilds.Values | Sort-Object) -join ", "
        $result.error_message = "Unsupported Windows version. Detected: $($os.Caption) (Build $($result.os_build)). Supported versions: $supportedVersions."
        return $result
    }
    catch {
        $result.error_message = "Failed to detect Windows Server version: $($_.Exception.Message)"
        return $result
    }
}

# Return SplunkForwarder service details (name/status/start_type) or $null if not present.
function Get-SplunkForwarderServiceInfo {
    $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    if (-not $svc) {
        return $null
    }

    $cimSvc = Get-CimInstance -ClassName Win32_Service -Filter "Name='SplunkForwarder'" -ErrorAction SilentlyContinue
    $info = @{
        name = $svc.Name
        status = $svc.Status.ToString()
    }
    if ($cimSvc) {
        $info.start_type = $cimSvc.StartMode
    }

    return $info
}

# Return installed Splunk UF version and release_id by executing splunk.exe.
# Returns a hashtable with 'version' and 'release_id' keys, or $null if not available.
function Get-InstalledSplunkForwarderVersionInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$installDir
    )

    $splunkExe = Join-Path $installDir "bin\splunk.exe"
    if (-not (Test-Path -LiteralPath $splunkExe)) {
        return $null
    }

    try {
        $out = & $splunkExe version 2>$null
        if (-not $out) { return $null }

        $text = ($out | Out-String)
        
        # Parse version (e.g., "Splunk Universal Forwarder 10.0.1 (build c486717c322b)")
        $versionMatch = [regex]::Match($text, "(\d+\.\d+\.\d+)")
        $releaseIdMatch = [regex]::Match($text, "\(build\s+([a-f0-9]+)\)")
        
        $result = @{
            version = $null
            release_id = $null
        }
        
        if ($versionMatch.Success) {
            $result.version = $versionMatch.Groups[1].Value
        }
        
        if ($releaseIdMatch.Success) {
            $result.release_id = $releaseIdMatch.Groups[1].Value
        }
        
        return $result
    }
    catch {
        return $null
    }
}

# Read the currently configured deployment server (deploy-poll)
function Get-CurrentDeployPoll {
    param(
        [Parameter(Mandatory = $true)]
        [string]$splunkExe
    )

    try {
        $out = & $splunkExe "show" "deploy-poll" 2>$null
        if ($out) {
            $text = ($out | Out-String)
            # Match IP:port pattern, excluding any surrounding quotes
            if ($text -match '([^\s]+:\d+)') {
                $result = $matches[1]
                # Strip any leading/trailing quotes
                $result = $result.Trim('"').Trim("'")
                return $result
            }
        }
    }
    catch { }

    return $null
}

# Return the currently configured forward servers (indexers) using splunk.exe.
function Get-CurrentForwardServers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$splunkExe
    )

    try {
        $out = & $splunkExe list "forward-server" 2>$null
        if (-not $out) { return @() }

        $text = ($out | Out-String)
        $serverMatches = [regex]::Matches($text, "(\S+:\d+)")
        $servers = @()
        foreach ($m in $serverMatches) { $servers += $m.Groups[1].Value }
        return @($servers | Select-Object -Unique)
    }
    catch {
        return @()
    }
}

# Test if the provided credentials work by attempting to authenticate with Splunk.
# Returns $true if credentials work, $false otherwise.
# Uses 'splunk login -auth' which is the explicit way to test authentication.
function Test-SplunkCredentials {
    param(
        [Parameter(Mandatory = $true)]
        [string]$splunkExe,
        [Parameter(Mandatory = $true)]
        [string]$username,
        [Parameter(Mandatory = $true)]
        [string]$password
    )

    if (-not (Test-Path -LiteralPath $splunkExe)) {
        return $false
    }

    try {
        # Use 'login -auth' to explicitly test credentials
        # Exit code 0 = successful authentication
        # Exit code 24 = login failed (invalid credentials)
        $authString = "${username}:${password}"
        $output = & $splunkExe login -auth $authString 2>&1
        $exitCode = $LASTEXITCODE

        # Exit code 0 means login succeeded - credentials are valid
        if ($exitCode -eq 0) {
            return $true
        }

        # Any other exit code (especially 24) means authentication failed
        return $false
    }
    catch {
        return $false
    }
}

# Export all functions
Export-ModuleMember -Function @(
    'Test-SupportedWindowsServer',
    'Get-SplunkForwarderServiceInfo',
    'Get-InstalledSplunkForwarderVersionInfo',
    'Get-CurrentDeployPoll',
    'Get-CurrentForwardServers',
    'Test-SplunkCredentials'
)

