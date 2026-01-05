#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, splunk.enterprise contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: win_splunk_universal_forwarder
short_description: Install and bootstrap Splunk Universal Forwarder on Windows
description:
  - Downloads the Splunk Universal Forwarder MSI for a requested version and installs it silently.
  - Seeds initial credentials via C(user-seed.conf) and configures deployment/forward servers using C(splunk.exe) authenticated via environment variables.
  - Supports upgrades to newer versions (downgrade is not supported).
  - Configures forward servers and deployment server.
version_added: "1.0.0"
options:
  state:
    description:
      - Whether the Splunk Universal Forwarder should be installed or removed.
    type: str
    choices: [present, absent]
    default: present
  purge:
    description:
      - When C(state=absent), purge Splunk UF files/config directories and temp directory after uninstall.
      - This will remove both the installation directory and the temp directory (default C(C:\splunktemp)) with all downloaded files.
      - Be careful with this option, as it will remove all files and the temp folder even if it was present before the module run.
    type: bool
    default: false
  version:
    description:
      - Splunk Universal Forwarder version to install or upgrade to (for example C(10.0.2)).
      - If a lower version than currently installed is specified, the module will fail with a downgrade error.
      - If the same version is already installed, only configuration changes will be applied.
      - If a higher version is specified, an upgrade will be performed.
    type: str
    required: false
  release_id:
    description:
      - Release identifier used in the download filename (for example C(e2d18b4767e9) for C(10.0.2)).
      - This is the suffix between the version and platform in the MSI filename.
      - "Example: C(splunkforwarder-<version>-<hash>-windows-x64.msi)."
    type: str
  temp_dir:
    description:
      - Directory on the Windows host to store the downloaded MSI and installation logs.
    type: str
    default: C:\splunktemp
  install_dir:
    description:
      - Installation directory for Splunk Universal Forwarder.
      - Also used for version detection and running C(splunk.exe) commands.
      - "IMPORTANT: This parameter cannot be changed after installation."
      - "The install directory is set during initial installation and cannot be moved via MSI upgrade."
      - "If you installed Splunk to a non-default directory, you MUST provide the same C(install_dir) value."
      - "This is required for all subsequent runs (upgrades, configuration changes, etc.)."
      - The module needs to know the correct installation directory to detect the installed version and execute commands.
    type: path
    default: C:\Program Files\SplunkUniversalForwarder
  splunk_username:
    description:
      - Initial Splunk admin username to write to C(user-seed.conf) and to authenticate C(splunk.exe) commands via environment variables.
      - Required when C(state=present).
    type: str
    required: false
  splunk_password:
    description:
      - Initial Splunk admin password to write to C(user-seed.conf) and to authenticate C(splunk.exe) commands via environment variables.
      - Required when C(state=present).
    type: str
    required: false
  forward_servers:
    description:
      - Desired list of forward servers in C(ip:port) format or hostname:port format.
      - To clear all configured forward servers, use an explicit empty list C(forward_servers{{':'}} []).
      - If omitted entirely, forward servers are not modified.
      - "Example: ['10.1.1.1:9997', 'domain.test.com:9997']"
    type: list
    elements: str
  deployment_server:
    description:
      - Deployment server in C(ip:port) format or hostname:port format.
      - To clear the configured deployment server, use the special value C("NONE").
      - When clearing, the module will remove C(deploymentclient.conf) and restart Splunk.
      - If omitted entirely, the deployment server configuration is not modified.
      - "Example: '10.1.1.1:8089' or 'domain.test.com:8089'"
    type: str
    required: false
  service_account_type:
    description:
      - Type of service account to use for running the Splunk Universal Forwarder service.
      - C(local_system) uses the Local System account (USE_LOCAL_SYSTEM=1).
      - C(virtual_service_account) uses a virtual service account (default MSI behavior without USE_LOCAL_SYSTEM).
      - This option is recommended for production environments.
      - When using C(virtual_service_account), there might be inconsistencies while installing.
      - Failures might occur; recommendation is to run with retry logic.
      - C(domain_user) uses a specific domain or local user account (requires C(service_logon_username) and C(service_logon_password)).
    type: str
    choices: [local_system, virtual_service_account, domain_user]
    default: local_system
  service_logon_username:
    description:
      - Username for the service account (in format C(domain\username) or C(.\username) for local accounts).
      - Required when C(service_account_type=domain_user).
      - This parameter specifies the user account that the SplunkForwarder service will run as.
    type: str
    required: false
  service_logon_password:
    description:
      - Password for the service account.
      - Required when C(service_account_type=domain_user).
    type: str
    required: false
notes:
  - When using C(service_account_type=domain_user), ensure the specified user has appropriate permissions to run services and access Splunk directories.
  - Upgrades are performed using the same msiexec command as installations. Downgrades are not supported.
  - When the same version is already installed, the module will only apply configuration changes (forward servers, deployment server, etc.).
  - If the MSI installer returns exit code 3010, a warning will be displayed indicating that a system reboot is required.
author:
  - Ron Gershburg (@rgershbu)
"""

EXAMPLES = r"""
- name: Install Splunk Universal Forwarder 10.0.2 with Local System account
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    forward_servers:
      - '10.46.30.200:9997'
      - 'domain.test.com:9997'
    deployment_server: '10.46.29.168:8089'
    service_account_type: local_system
- name: Install Splunk Universal Forwarder with custom installation directory
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.0'
    release_id: 'e8eb0c4654f8'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    install_dir: 'D:\Splunk\UniversalForwarder'
    forward_servers:
      - '10.46.30.200:9997'
      - 'domain.test.com:9997'
- name: Upgrade with custom installation directory (must specify same install_dir)
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    install_dir: 'D:\Splunk\UniversalForwarder'
    forward_servers:
      - '10.46.30.200:9997'
      - 'domain.test.com:9997'
- name: Update configuration with custom installation directory
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    install_dir: 'D:\Splunk\UniversalForwarder'
    forward_servers:
      - '10.46.30.200:9997'
      - 'domain.test.com:9997'
- name: Install Splunk Universal Forwarder with Virtual Service Account (with retry)
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    forward_servers:
      - '10.46.30.200:9997'
      - 'domain.test.com:9997'
    service_account_type: virtual_service_account
  register: splunk_install_result
  retries: 5
  delay: 5
  until: splunk_install_result is succeeded
- name: Install Splunk Universal Forwarder with Domain User account
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    forward_servers:
      - '10.46.30.200:9997'
      - 'domain.test.com:9997'
    service_account_type: domain_user
    service_logon_username: 'DOMAIN\splunksvc'
    service_logon_password: 'SecureP@ss123'
- name: Remove all forward servers
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    forward_servers: []
- name: Clear deployment server configuration
  splunk.enterprise.win_splunk_universal_forwarder:
    version: '10.0.2'
    release_id: 'e2d18b4767e9'
    splunk_username: 'SplunkAdmin'
    splunk_password: 'Ch@ng3d!'
    deployment_server: 'NONE'
- name: Uninstall Splunk Universal Forwarder (preserve config and temp files)
  splunk.enterprise.win_splunk_universal_forwarder:
    state: absent
- name: Uninstall Splunk Universal Forwarder (remove all files including temp directory)
  splunk.enterprise.win_splunk_universal_forwarder:
    state: absent
    purge: true
"""

RETURN = r"""
changed:
  description: Whether the module made any changes.
  type: bool
  returned: always
version_comparison:
  description: Result of version comparison (-1 if installed < requested, 0 if equal, 1 if installed > requested).
  type: int
  returned: when state=present and version is already installed
download_url:
  description: URL used to download the MSI.
  type: str
  returned: when state=present
checksum_url:
  description: URL used to download the SHA512 checksum file.
  type: str
  returned: when state=present
msi_path:
  description: Full path where the MSI was stored on the Windows host.
  type: str
  returned: when state=present
checksum_path:
  description: Full path where the SHA512 checksum file was stored on the Windows host.
  type: str
  returned: when state=present
installed:
  description: Whether the SplunkForwarder service is present after execution.
  type: bool
  returned: always
installed_version:
  description: Installed version detected via C(splunk.exe version) (best-effort).
  type: str
  returned: when state=present
service:
  description: SplunkForwarder service details.
  type: dict
  returned: always
  contains:
    name:
      description: Service name.
      type: str
    status:
      description: Service status (Running, Stopped, etc.).
      type: str
    start_type:
      description: Service startup type (Automatic, Manual, etc.).
      type: str
reboot_required:
  description: Whether the MSI returned 3010 indicating a reboot is required.
  type: bool
  returned: always
purged_install_dir:
  description: Whether the installation directory was successfully purged during uninstall.
  type: bool
  returned: when state=absent and purge=true
purged_temp_dir:
  description: Whether the temp directory was successfully purged during uninstall.
  type: bool
  returned: when state=absent and purge=true
splunk_stop_attempted:
  description: Whether the module attempted to stop Splunk before uninstalling.
  type: bool
  returned: when state=absent
splunk_stopped:
  description: Whether the Splunk service was successfully stopped before uninstall.
  type: bool
  returned: when state=absent and splunk_stop_attempted is true
splunk_stop_error:
  description: Error message if stopping Splunk failed.
  type: str
  returned: when state=absent and splunk_stopped is false
deploymentclient_conf_removed:
  description: Whether deploymentclient.conf was removed when clearing deployment server.
  type: bool
  returned: when deployment_server is set to NONE
splunk_restarted_for_deploy_clear:
  description: Whether Splunk was restarted after clearing deployment server.
  type: bool
  returned: when deployment_server is set to NONE
"""
