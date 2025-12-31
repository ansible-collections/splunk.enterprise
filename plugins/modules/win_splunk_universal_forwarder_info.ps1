#!powershell

# Copyright: (c) 2025, splunk.enterprise contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils.splunk_uf_windows_utils

$ErrorActionPreference = "Stop"

$spec = @{
    options = @{
        username = @{ type = "str"; required = $true }
        password = @{ type = "str"; required = $true; no_log = $true }
        install_dir = @{ type = "path"; required = $false; default = "C:\Program Files\SplunkUniversalForwarder" }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

# Validate Windows Server version
$osCheck = Test-SupportedWindowsServer
if (-not $osCheck.is_supported) {
    $module.FailJson($osCheck.error_message)
}

try {
    $username = $module.Params.username
    $password = $module.Params.password
    $installDir = $module.Params.install_dir

    # Initialize result
    $module.Result.changed = $false
    $module.Result.splunk_home = $installDir

    # Define splunk.exe path
    $splunkExe = Join-Path $installDir "bin\splunk.exe"
    $splunkExeExists = Test-Path -LiteralPath $splunkExe

    # Check if Splunk is installed
    $svcInfo = Get-SplunkForwarderServiceInfo
    $isInstalled = ($null -ne $svcInfo) -or $splunkExeExists

    if (-not $isInstalled) {
        $module.Result.state = "absent"
        $module.ExitJson()
    }

    # Splunk is installed
    $module.Result.state = "present"
    $module.Result.service = $svcInfo

    # Get version and release_id
    $versionInfo = Get-InstalledSplunkForwarderVersionInfo -installDir $installDir
    if ($versionInfo) {
        if ($versionInfo.version) {
            $module.Result.version = $versionInfo.version
        }
        if ($versionInfo.release_id) {
            $module.Result.release_id = $versionInfo.release_id
        }
    }

    # Set credentials env vars for splunk.exe authentication
    $env:SPLUNK_USERNAME = $username
    $env:SPLUNK_PASSWORD = $password

    # Test credentials before attempting to retrieve configuration
    if ($splunkExeExists) {
        $credentialsWork = Test-SplunkCredential -splunkExe $splunkExe -username $username -password $password

        if (-not $credentialsWork) {
            $module.FailJson("The provided credentials are invalid. Please provide correct Splunk admin credentials.")
        }

        # Get forward servers
        $forwardServers = Get-CurrentForwardServer -splunkExe $splunkExe
        $module.Result.forward_servers = [string[]]@($forwardServers)

        # Get deployment server
        $deploymentServer = Get-CurrentDeployPoll -splunkExe $splunkExe
        if ($deploymentServer) {
            $module.Result.deployment_server = $deploymentServer
        }
    }

    $module.ExitJson()
}
catch {
    $module.FailJson($_.Exception.Message)
}
