#!powershell

# Copyright: (c) 2025, splunk.enterprise contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils.splunk_uf_windows_utils

$ErrorActionPreference = "Stop"

$spec = @{
    options = @{
        state = @{ type = "str"; required = $false; default = "present"; choices = @("present", "absent") }
        purge = @{ type = "bool"; required = $false; default = $false }
        version = @{ type = "str"; required = $false }
        release_id = @{ type = "str"; required = $false }
        temp_dir = @{ type = "str"; required = $false; default = "C:\splunktemp" }
        install_dir = @{ type = "path"; required = $false; default = "C:\Program Files\SplunkUniversalForwarder" }
        splunk_username = @{ type = "str"; required = $false }
        splunk_password = @{ type = "str"; required = $false; no_log = $true }
        forward_servers = @{
            type = "list"
            elements = "str"
            required = $false
            default = $null
        }
        deployment_server = @{ type = "str"; required = $false }
        service_account_type = @{
            type = "str"
            required = $false
            default = "local_system"
            choices = @("local_system", "virtual_service_account", "domain_user")
        }
        service_logon_username = @{ type = "str"; required = $false }
        service_logon_password = @{ type = "str"; required = $false; no_log = $true }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

# Validate Windows Server version
$osCheck = Test-SupportedWindowsServer
if (-not $osCheck.is_supported) {
    $module.FailJson($osCheck.error_message)
}

# Validate service account parameters
$serviceAccountType = $module.Params.service_account_type
$serviceLogonUsername = $module.Params.service_logon_username
$serviceLogonPassword = $module.Params.service_logon_password

if ($serviceAccountType -eq "domain_user") {
    if (-not $serviceLogonUsername) {
        $module.FailJson("Parameter 'service_logon_username' is required when service_account_type=domain_user.")
    }
    if (-not $serviceLogonPassword) {
        $module.FailJson("Parameter 'service_logon_password' is required when service_account_type=domain_user.")
    }
}

# Initialize directory (create it if missing) and return whether it was created.
function Initialize-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$path
    )

    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
        return $true
    }

    return $false
}

# Poll until the SplunkForwarder service exists and is Running, or fail after a timeout.
function Wait-ForSplunkForwarderRunning {
    param(
        [int]$timeoutSeconds = 60,
        [int]$sleepSeconds = 5
    )

    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $timeoutSeconds) {
        $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            return
        }
        Start-Sleep -Seconds $sleepSeconds
    }

    $module.FailJson(("Timed out waiting for SplunkForwarder service to be Running after {0}s." -f $timeoutSeconds))
}

# Discover Splunk Universal Forwarder install metadata from registry uninstall keys.
function Get-SplunkForwarderRegistryInstall {
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($registryPath in $registryPaths) {
        # Use Get-ChildItem to enumerate subkeys, then Get-ItemProperty with -LiteralPath
        $keys = Get-ChildItem -LiteralPath $registryPath -ErrorAction SilentlyContinue
        foreach ($key in $keys) {
            $item = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $item -or -not $item.DisplayName) { continue }

            # Need to be careful in general, not to match other Splunk products.
            $isUniversalForwarder = ($item.DisplayName -like "*Splunk Universal Forwarder*") -or
                ($item.DisplayName -like "*Universal Forwarder*") -or
                ($item.DisplayName -like "*UniversalForwarder*")
            if ($isUniversalForwarder) {
                $keyName = $key.PSChildName
                $productCode = $null
                if ($keyName -match "^\{[0-9A-Fa-f-]+\}$") {
                    $productCode = $keyName
                }

                return @{
                    display_name = $item.DisplayName
                    display_version = $item.DisplayVersion
                    install_location = $item.InstallLocation
                    uninstall_string = $item.UninstallString
                    quiet_uninstall_string = $item.QuietUninstallString
                    product_code = $productCode
                }
            }
        }
    }

    return $null
}

# Return installed Splunk UF version by executing splunk.exe or $null.
# Wrapper around Get-InstalledSplunkForwarderVersionInfo from shared utils.
function Get-InstalledSplunkForwarderVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$installDir
    )

    $versionInfo = Get-InstalledSplunkForwarderVersionInfo -installDir $installDir
    if ($versionInfo -and $versionInfo.version) {
        return $versionInfo.version
    }
    return $null
}

# Compare two semantic versions (X.Y.Z format).
# Returns: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
function Compare-SemanticVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$version1,
        [Parameter(Mandatory = $true)]
        [string]$version2
    )

    $v1Parts = $version1 -split '\.'
    $v2Parts = $version2 -split '\.'

    for ($i = 0; $i -lt 3; $i++) {
        $v1Num = 0
        $v2Num = 0

        if ($i -lt $v1Parts.Count) {
            [int]::TryParse($v1Parts[$i], [ref]$v1Num) | Out-Null
        }
        if ($i -lt $v2Parts.Count) {
            [int]::TryParse($v2Parts[$i], [ref]$v2Num) | Out-Null
        }

        if ($v1Num -lt $v2Num) { return -1 }
        if ($v1Num -gt $v2Num) { return 1 }
    }

    return 0
}

# Download a file to a destination path (forces TLS 1.2 where possible).
function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$url,
        [Parameter(Mandatory = $true)]
        [string]$destPath
    )

    # Ensure TLS 1.2 for downloads (Windows PowerShell 5.1 often defaults to TLS 1.0)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # Silently continue if TLS 1.2 is not available or already set
        $null = $_
    }

    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $url -OutFile $destPath -UseBasicParsing
}

# Verify SHA512 checksum of a downloaded file against a checksum file.
function Test-FileChecksum {
    param(
        [Parameter(Mandatory = $true)]
        [string]$filePath,
        [Parameter(Mandatory = $true)]
        [string]$checksumFilePath
    )

    if (-not (Test-Path -LiteralPath $filePath)) {
        throw "File to verify does not exist: $filePath"
    }

    if (-not (Test-Path -LiteralPath $checksumFilePath)) {
        throw "Checksum file does not exist: $checksumFilePath"
    }

    # Read the checksum file content
    $checksumContent = Get-Content -LiteralPath $checksumFilePath -Raw

    # Parse the expected hash from the checksum file
    if ($checksumContent -match 'SHA512\([^\)]+\)=\s*([0-9a-fA-F]+)') {
        $expectedHash = $matches[1].Trim().ToUpper()
    }
    else {
        throw "Unable to parse SHA512 hash from checksum file: $checksumFilePath"
    }

    # Compute the actual hash of the downloaded file
    $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA512).Hash.ToUpper()

    # Compare the hashes
    if ($actualHash -ne $expectedHash) {
        throw "Checksum verification failed for file: $filePath. Expected: $expectedHash, Got: $actualHash"
    }
}

# Install or upgrade Splunk Universal Forwarder using msiexec.
# Returns a hashtable with install results.
function Install-SplunkUniversalForwarder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$msiPath,
        [Parameter(Mandatory = $true)]
        [string]$splunkPassword,
        [Parameter(Mandatory = $true)]
        [string]$serviceAccountType,
        [Parameter(Mandatory = $false)]
        [string]$serviceLogonUsername,
        [Parameter(Mandatory = $false)]
        [string]$serviceLogonPassword,
        [Parameter(Mandatory = $true)]
        [string]$tempDir,
        [Parameter(Mandatory = $false)]
        [string]$installDir
    )

    $result = @{
        exitCode = 0
        rebootRequired = $false
    }

    $msiArgs = @(
        "/i", "`"$msiPath`"",
        "AGREETOLICENSE=Yes",
        "/l*v", "`"$(Join-Path $tempDir 'splunk_install.log')`""
    )

    # Add installation directory if specified
    if (-not [string]::IsNullOrWhiteSpace($installDir)) {
        $msiArgs += "INSTALLDIR=`"$installDir`""
    }

    # Add service account configuration based on type
    switch ($serviceAccountType) {
        "local_system" {
            # Use Local System account
            $msiArgs += "USE_LOCAL_SYSTEM=1"
        }
        "virtual_service_account" {
            # Virtual service account is the default MSI behavior
            # Do not add USE_LOCAL_SYSTEM parameter
        }
        "domain_user" {
            # Use specific domain or local user account
            $msiArgs += "LOGON_USERNAME=`"$serviceLogonUsername`""
            $msiArgs += "LOGON_PASSWORD=`"$serviceLogonPassword`""
        }
    }

    $msiArgs += "/qn"
    $msiArgs += "/norestart"

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    $result.exitCode = $proc.ExitCode

    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        $module.FailJson("msiexec install/upgrade failed with exit code $($proc.ExitCode)")
    }

    if ($proc.ExitCode -eq 3010) {
        $result.rebootRequired = $true
        $module.Warn("A system reboot is required to complete the Splunk Universal Forwarder installation/upgrade. MSI returned exit code 3010.")
    }

    return $result
}

# Compute which splunk.exe configuration actions are needed (deploy-poll, forward-server).
# If splunk.exe is not available (for example during check mode before install), treat current state as empty.
function Get-DesiredSplunkConfigPlan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$splunkExe,
        [Parameter(Mandatory = $false)]
        $desiredDeploymentServer,
        [Parameter(Mandatory = $false)]
        [bool]$clearDeploymentServer = $false,
        [Parameter(Mandatory = $false)]
        [string[]]$desiredForwardServers,
        [Parameter(Mandatory = $false)]
        [bool]$treatCurrentStateAsEmpty = $false
    )

    $plan = @{
        wouldSetDeployPoll = $false
        wouldClearDeployPoll = $false
        wouldAddForwardServers = [string[]]@()
        wouldRemoveForwardServers = [string[]]@()
    }

    if ($treatCurrentStateAsEmpty -or (-not (Test-Path -LiteralPath $splunkExe))) {
        # No splunk.exe to query; assume nothing is configured yet.
        if ($clearDeploymentServer) {
            $plan.wouldSetDeployPoll = $true
            $plan.wouldClearDeployPoll = $true
        }
        elseif ($desiredDeploymentServer) {
            $plan.wouldSetDeployPoll = $true
        }
        # Check if desiredForwardServers is a list (even if empty)
        if ($null -ne $desiredForwardServers -and $desiredForwardServers -is [System.Collections.IList]) {
            $plan.wouldAddForwardServers = [string[]]@($desiredForwardServers | Select-Object -Unique)
            $plan.wouldRemoveForwardServers = [string[]]@()
        }
        return $plan
    }

    $currentDeployPoll = Get-CurrentDeployPoll -splunkExe $splunkExe

    # Handle deployment server
    if ($clearDeploymentServer) {
        # User explicitly requested to clear deployment server
        if ($currentDeployPoll) {
            $plan.wouldSetDeployPoll = $true
            $plan.wouldClearDeployPoll = $true
        }
    }
    elseif ($desiredDeploymentServer) {
        # User wants to set deployment server (not null/empty)
        if ($currentDeployPoll -ne $desiredDeploymentServer) {
            $plan.wouldSetDeployPoll = $true
        }
    }
    # else: both are null/false/empty, don't touch deployment server

    $currentForwardServers = Get-CurrentForwardServer -splunkExe $splunkExe
    # Check if desiredForwardServers is a list (even if empty)
    if ($null -ne $desiredForwardServers -and $desiredForwardServers -is [System.Collections.IList]) {
        $desiredSet = [string[]]@($desiredForwardServers | Select-Object -Unique)
        $currentSet = [string[]]@($currentForwardServers | Select-Object -Unique)
        $plan.wouldAddForwardServers = [string[]]@($desiredSet | Where-Object { $_ -notin $currentSet })
        $plan.wouldRemoveForwardServers = [string[]]@($currentSet | Where-Object { $_ -notin $desiredSet })
    }

    return $plan
}

try {
    $state = $module.Params.state
    $purge = $module.Params.purge
    $version = $module.Params.version
    $releaseId = $module.Params.release_id
    $tempDir = $module.Params.temp_dir
    $installDir = $module.Params.install_dir

    $splunkUsername = $module.Params.splunk_username
    $splunkPassword = $module.Params.splunk_password
    $forwardServers = $module.Params.forward_servers
    $deploymentServer = $module.Params.deployment_server

    $module.Result.changed = $false
    $module.Result.reboot_required = $false
    $module.Result.service = $null
    $module.Result.installed = $false
    $module.Result.installed_version = $null
    $module.Result.download_url = $null
    $module.Result.msi_path = $null

    $svcInfo = Get-SplunkForwarderServiceInfo
    $regInfo = Get-SplunkForwarderRegistryInstall

    # Define splunk.exe path once for use throughout the module
    $splunkExe = Join-Path $installDir "bin\splunk.exe"
    $splunkExeExists = Test-Path -LiteralPath $splunkExe
    $isInstalled = ($null -ne $svcInfo) -or $splunkExeExists
    $module.Result.installed = $isInstalled
    $module.Result.service = $svcInfo

    if ($state -eq "present") {
        # Required params for state=present
        foreach ($requiredName in @("version", "release_id", "splunk_username", "splunk_password")) {
            if (-not $module.Params.$requiredName) {
                $module.FailJson(("Parameter '{0}' is required when state=present." -f $requiredName))
            }
        }
        $baseUrl = "https://download.splunk.com/products/universalforwarder/releases/$version/windows"
        $msiFilename = "splunkforwarder-$version-$releaseId-windows-x64.msi"
        $msiPath = Join-Path $tempDir $msiFilename
        $downloadUrl = "$baseUrl/$msiFilename"
        $checksumFilename = "$msiFilename.sha512"
        $checksumPath = Join-Path $tempDir $checksumFilename
        $checksumUrl = "$baseUrl/$checksumFilename"

        $module.Result.download_url = $downloadUrl
        $module.Result.msi_path = $msiPath
        $module.Result.checksum_url = $checksumUrl
        $module.Result.checksum_path = $checksumPath

        $installedVersion = $null
        if ($isInstalled) {
            $installedVersion = Get-InstalledSplunkForwarderVersion -installDir $installDir
            if (-not $installedVersion -and $regInfo -and $regInfo.display_version) {
                $installedVersion = $regInfo.display_version
            }
        }
        $module.Result.installed_version = $installedVersion

        # Determine if we need to install/upgrade based on version comparison
        $wouldInstall = $false
        $wouldUpgrade = $false

        if (-not $isInstalled) {
            $wouldInstall = $true
        }
        elseif ($installedVersion) {
            $versionComparison = Compare-SemanticVersion -version1 $installedVersion -version2 $version
            $module.Result.version_comparison = $versionComparison

            # Installed version is lower than requested version - upgrade needed
            if ($versionComparison -lt 0) {
                $wouldUpgrade = $true
            }

            # Installed version is higher - downgrade not supported
            elseif ($versionComparison -gt 0) {
                $errMsg = "Downgrade is not supported. Installed version " +
                "($installedVersion) is higher than requested version " +
                "($version). Please uninstall the current version first."
                $module.FailJson($errMsg)
            }
            # Same version - no action needed (no else block needed)
        }
        else {
            # Installed but cannot determine version - treat as needs install
            $wouldInstall = $true
        }

        # Deployment server handling:
        $desiredDeploymentServer = $null
        $shouldClearDeploymentServer = $false

        if ($null -ne $deploymentServer) {
            # Special value "NONE" means clear deployment server
            if ($deploymentServer -eq "NONE") {
                $shouldClearDeploymentServer = $true
            }
            else {
                # Valid server:port provided - validate format and set deployment server
                $parts = $deploymentServer -split ":", 2
                if ($parts.Count -ne 2) {
                    $module.FailJson("deployment_server must be in 'ip:port' format or 'NONE' to clear. Invalid: '$deploymentServer'")
                }

                $ip = $parts[0].Trim()
                $portStr = $parts[1].Trim()

                if ([string]::IsNullOrWhiteSpace($ip)) {
                    $module.FailJson("IP/hostname cannot be empty in deployment_server: '$deploymentServer'")
                }

                try {
                    $portInt = [int]$portStr
                    if ($portInt -le 0 -or $portInt -gt 65535) {
                        $module.FailJson("Port must be between 1 and 65535 in deployment_server: '$deploymentServer'")
                    }
                }
                catch {
                    $module.FailJson("Port must be a valid integer in deployment_server: '$deploymentServer'")
                }

                $desiredDeploymentServer = "{0}:{1}" -f $ip, $portInt
            }
        }

        $desiredForwardServers = $null

        # Ansible.Basic returns System.Collections.Generic.List which implements IList
        if ($null -ne $forwardServers -and $forwardServers -is [System.Collections.IList]) {
            $tmpDesired = @()
            foreach ($serverStr in $forwardServers) {
                # Skip null/empty entries that might come from YAML parsing
                if ($null -eq $serverStr -or [string]::IsNullOrWhiteSpace($serverStr)) { continue }

                # Parse "ip:port" format
                $parts = $serverStr -split ":", 2
                if ($parts.Count -ne 2) {
                    $module.FailJson("forward_servers entries must be in 'ip:port' format. Invalid: '$serverStr'")
                }

                $ip = $parts[0].Trim()
                $portStr = $parts[1].Trim()

                if ([string]::IsNullOrWhiteSpace($ip)) {
                    $module.FailJson("IP address cannot be empty in forward_servers entry: '$serverStr'")
                }

                try {
                    $portInt = [int]$portStr
                    if ($portInt -le 0 -or $portInt -gt 65535) {
                        $module.FailJson("Port must be between 1 and 65535 in forward_servers entry: '$serverStr'")
                    }
                }
                catch {
                    $module.FailJson("Port must be a valid integer in forward_servers entry: '$serverStr'")
                }

                $tmpDesired += ("{0}:{1}" -f $ip, $portInt)
            }
            # Set desiredForwardServers to the array (empty or with values)
            $desiredForwardServers = [string[]]@($tmpDesired | Select-Object -Unique)
        }

        $seedFile = Join-Path $installDir "etc\system\local\user-seed.conf"
        $desiredSeed = @"
[user_info]
USERNAME = $splunkUsername
PASSWORD = $splunkPassword
"@

        # Check if we need to write/update the seed file
        # Only write seed on new install. On existing install, verify credentials work.
        $wouldWriteSeed = $false

        if ($wouldInstall) {
            # New install - we'll need to set credentials
            $wouldWriteSeed = $true
        }
        elseif ($isInstalled -and $splunkExeExists) {
            # Splunk is already installed - test if the provided credentials work
            $credentialsWork = Test-SplunkCredential -splunkExe $splunkExe -username $splunkUsername -password $splunkPassword

            if (-not $credentialsWork) {
                $errMsg = "Splunk Universal Forwarder is already installed " +
                "but the provided credentials are invalid. " +
                "Please provide the correct credentials."
                $module.FailJson($errMsg)
            }

            # Credentials are valid - no need to update
            $wouldWriteSeed = $false
        }
        else {
            # Edge case: installed but no splunk.exe (shouldn't happen normally)
            $wouldWriteSeed = $true
        }

        $wouldSetDeployPoll = $false
        $wouldAddForwardServers = [string[]]@()
        $wouldRemoveForwardServers = [string[]]@()


        if (($wouldInstall -or $wouldUpgrade) -and (-not $module.CheckMode)) {
            $module.Result.changed = $true

            Initialize-Directory -path $tempDir | Out-Null

            # Check if files already exist
            $msiExists = Test-Path -LiteralPath $msiPath
            $checksumExists = Test-Path -LiteralPath $checksumPath
            $needsDownload = $false

            # If both files exist, try to verify checksum first
            if ($msiExists -and $checksumExists) {
                try {
                    Test-FileChecksum -filePath $msiPath -checksumFilePath $checksumPath
                }
                catch {
                    # Checksum verification failed - need to re-download
                    $needsDownload = $true
                }
            }
            else {
                # One or both files missing - need to download
                $needsDownload = $true
            }

            # Download files if needed
            if ($needsDownload) {
                # Download the SHA512 checksum file first
                try {
                    Invoke-DownloadFile -url $checksumUrl -destPath $checksumPath
                }
                catch {
                    $module.FailJson("Failed to download checksum file from ${checksumUrl}: $($_.Exception.Message)")
                }

                # Download the MSI installer
                try {
                    Invoke-DownloadFile -url $downloadUrl -destPath $msiPath
                }
                catch {
                    $module.FailJson("Failed to download MSI from ${downloadUrl}: $($_.Exception.Message)")
                }

                # Verify the checksum
                try {
                    Test-FileChecksum -filePath $msiPath -checksumFilePath $checksumPath
                }
                catch {
                    $module.FailJson("Checksum verification failed: $($_.Exception.Message)")
                }
            }

            # This is comemnted for now to check whether this is even needed.
            # # If the product is registered in MSI but UF binaries/service are missing, clean up the broken state
            # if ($wouldInstall -and $regInfo -and $regInfo.product_code -and (-not $splunkExeExists) -and ($null -eq $svcInfo)) {
            #     $uninstallArgs = @(
            #         "/x", $regInfo.product_code,
            #         "/qn",
            #         "/norestart"
            #     )
            #     $uninstallProc = Start-Process -FilePath "msiexec.exe" -ArgumentList $uninstallArgs -Wait -PassThru
            #     if ($uninstallProc.ExitCode -ne 0 -and $uninstallProc.ExitCode -ne 3010) {
            #         $module.FailJson(("msiexec uninstall (cleanup) failed with exit code {0}." -f $uninstallProc.ExitCode))
            #     }
            #     if ($uninstallProc.ExitCode -eq 3010) {
            #         $module.Result.reboot_required = $true
            #         $module.Warn("A system reboot is required after pre-install cleanup. MSI returned exit code 3010.")
            #     }
            # }

            # Perform install or upgrade using the unified function
            $installResult = Install-SplunkUniversalForwarder `
                -msiPath $msiPath `
                -splunkPassword $splunkPassword `
                -serviceAccountType $serviceAccountType `
                -serviceLogonUsername $serviceLogonUsername `
                -serviceLogonPassword $serviceLogonPassword `
                -tempDir $tempDir `
                -installDir $installDir

            if ($installResult.rebootRequired) {
                $module.Result.reboot_required = $true
            }

            # Wait for service existence (it may be created by MSI but not started yet).
            Wait-ForSplunkForwarderRunning -timeoutSeconds 60 -sleepSeconds 5
        }
        elseif (-not $module.CheckMode) {
            # If it is already installed, ensure service is running before configuring.
            # Only wait if the service actually exists; registry keys alone can be stale.
            if ($null -ne $svcInfo) {
                Wait-ForSplunkForwarderRunning -timeoutSeconds 60 -sleepSeconds 5
            }
        }

        # Refresh service info after install/wait.
        $svcInfo = Get-SplunkForwarderServiceInfo
        $module.Result.service = $svcInfo
        $module.Result.installed = ($null -ne $svcInfo) -or (Test-Path -LiteralPath $splunkExe)

        # Write/update seed file only if needed (new install or invalid credentials)
        if ($wouldWriteSeed -and (-not $module.CheckMode)) {
            $module.Result.changed = $true
            $passwdPath = Join-Path $installDir "etc\passwd"

            if (Test-Path -LiteralPath $passwdPath) {
                Remove-Item -LiteralPath $passwdPath -Force -ErrorAction SilentlyContinue
            }

            Initialize-Directory -path (Split-Path -Parent $seedFile) | Out-Null
            Set-Content -LiteralPath $seedFile -Value $desiredSeed -Encoding Ascii

            if (Test-Path -LiteralPath $splunkExe) {
                & $splunkExe restart --no-prompt 2>$null | Out-Null
                Wait-ForSplunkForwarderRunning -timeoutSeconds 60 -sleepSeconds 5
            }
        }

        # Set credentials env vars for splunk.exe authentication in this module invocation
        $env:SPLUNK_USERNAME = $splunkUsername
        $env:SPLUNK_PASSWORD = $splunkPassword

        # Determine if we can query current Splunk state (depends on UF being usable)
        $serviceRunningForQuery = ($null -ne $svcInfo) -and ($svcInfo.status -eq "Running")
        $canQueryCurrentState = (Test-Path -LiteralPath $splunkExe) -and $serviceRunningForQuery
        $treatCurrentStateAsEmpty = (-not $canQueryCurrentState)

        $plan = Get-DesiredSplunkConfigPlan `
            -splunkExe $splunkExe `
            -desiredDeploymentServer $desiredDeploymentServer `
            -clearDeploymentServer $shouldClearDeploymentServer `
            -desiredForwardServers $desiredForwardServers `
            -treatCurrentStateAsEmpty $treatCurrentStateAsEmpty
        $wouldSetDeployPoll = [bool]$plan.wouldSetDeployPoll
        $wouldClearDeployPoll = [bool]$plan.wouldClearDeployPoll
        $wouldAddForwardServers = [string[]]@($plan.wouldAddForwardServers)
        $wouldRemoveForwardServers = [string[]]@($plan.wouldRemoveForwardServers)

        # Verify check-mode returns the correct changed result.
        if ($module.CheckMode) {
            $hasForwardServerChanges = ($wouldAddForwardServers.Count -gt 0) -or `
            ($wouldRemoveForwardServers.Count -gt 0)

            $module.Result.changed = $wouldInstall -or $wouldUpgrade -or `
            ($wouldWriteSeed ) -or ($wouldSetDeployPoll) -or ($hasForwardServerChanges)
            $module.ExitJson()
        }

        # Configure via splunk.exe (fail if splunk.exe missing after install)
        if (-not (Test-Path -LiteralPath $splunkExe)) {
            $module.FailJson(("splunk.exe not found at expected path '{0}'" -f $splunkExe))
        }

        if ($wouldSetDeployPoll) {
            $module.Result.changed = $true
            if ($wouldClearDeployPoll) {
                # Clear deployment server by removing deploymentclient.conf and restarting
                $deploymentClientConf = Join-Path $installDir "etc\system\local\deploymentclient.conf"
                if (Test-Path -LiteralPath $deploymentClientConf) {
                    Remove-Item -LiteralPath $deploymentClientConf -Force -ErrorAction SilentlyContinue
                    $module.Result.deploymentclient_conf_removed = $true
                }
                else {
                    $module.Result.deploymentclient_conf_removed = $false
                }

                # Restart Splunk to apply the change
                if (Test-Path -LiteralPath $splunkExe) {
                    & $splunkExe restart --no-prompt 2>$null | Out-Null
                    $module.Result.splunk_restarted_for_deploy_clear = $true
                    Wait-ForSplunkForwarderRunning -timeoutSeconds 60 -sleepSeconds 5
                }
            }
            else {
                # Set deployment server to the desired value
                & $splunkExe set "deploy-poll" $desiredDeploymentServer 2>$null | Out-Null
            }
        }
        foreach ($fs in $wouldAddForwardServers) {
            $module.Result.changed = $true
            & $splunkExe add "forward-server" $fs 2>$null | Out-Null
        }
        foreach ($fs in $wouldRemoveForwardServers) {
            $module.Result.changed = $true
            & $splunkExe remove "forward-server" $fs 2>$null | Out-Null
        }

        $module.Result.installed_version = Get-InstalledSplunkForwarderVersion -installDir $installDir
        $module.ExitJson()
    }
    elseif ($state -eq "absent") {
        if (-not $isInstalled) {
            $module.ExitJson()
        }
        # splunk forwarder is installed but since this is check-mode we are not going to uninstall it.
        if ($module.CheckMode) {
            $module.Result.changed = $true
            $module.ExitJson()
        }

        # Stop Splunk service before uninstalling
        if (Test-Path -LiteralPath $splunkExe) {
            try {
                $module.Result.splunk_stop_attempted = $true
                & $splunkExe stop 2>$null | Out-Null
                $module.Result.splunk_stopped = $true
                # Give the service time to stop gracefully
                Start-Sleep -Seconds 5
            }
            catch {
                $module.Result.splunk_stopped = $false
                $module.Result.splunk_stop_error = $_.Exception.Message
                # Continue with uninstall even if stop fails
            }
        }
        else {
            $module.Result.splunk_stop_attempted = $false
        }

        if ($regInfo -and $regInfo.product_code -and (($null -ne $svcInfo) -or $splunkExeExists)) {
            $module.Result.changed = $true
            $argsX = @("/x", $regInfo.product_code, "/qn", "/norestart")
            $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $argsX -Wait -PassThru
            if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
                $module.FailJson(("msiexec uninstall failed with exit code {0}" -f $proc.ExitCode))
            }
            if ($proc.ExitCode -eq 3010) {
                $module.Result.reboot_required = $true
                $module.Warn("A system reboot is required to complete the Splunk Universal Forwarder uninstallation. MSI returned exit code 3010.")
            }
        }
        else {
            $module.FailJson("Unable to determine product code from registry for MSI uninstall.")
        }

        # Wait for service to disappear/stop.
        $start = Get-Date
        while (((Get-Date) - $start).TotalSeconds -lt 300) {
            $svc = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
            if (-not $svc) { break }
            Start-Sleep -Seconds 5
        }

        if ($purge) {
            $module.Result.changed = $true

            # Remove installation directory
            $purgeDir = $installDir
            if ($regInfo -and $regInfo.install_location) { $purgeDir = $regInfo.install_location }
            if ($purgeDir -and (Test-Path -LiteralPath $purgeDir)) {
                Remove-Item -LiteralPath $purgeDir -Recurse -Force -ErrorAction SilentlyContinue
                $module.Result.purged_install_dir = $true
            }
            else {
                $module.Result.purged_install_dir = $false
            }

            # Remove temp directory and its contents
            if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
                Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                $module.Result.purged_temp_dir = $true
            }
            else {
                $module.Result.purged_temp_dir = $false
            }
        }

        $module.Result.service = Get-SplunkForwarderServiceInfo
        $module.Result.installed = $false
        $module.ExitJson()
    }
    else {
        $module.FailJson(("Invalid state '{0}'." -f $state))
    }
}
catch {
    $module.FailJson($_.Exception.Message)
}
