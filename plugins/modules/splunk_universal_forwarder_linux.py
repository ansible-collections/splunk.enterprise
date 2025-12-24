#!/usr/bin/python

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: splunk_universal_forwarder_linux

short_description: Manage Splunk Universal Forwarder installations on RHEL systems

description:
  - This module manages Splunk Universal Forwarder installations on RHEL 8, 9, and 10 systems using RPM packages.
  - Downloads the Splunk Universal Forwarder RPM and verifies its integrity using SHA512 checksums.
  - Supports idempotent installation and removal of the forwarder.
  - Automatically configures user credentials and starts the forwarder on first installation.

version_added: "1.0.0"

author:
  - Shahar Golshani (@shahargolshani)

attributes:
  check_mode:
    support: full
  diff_mode:
    support: none

options:
  state:
    description:
      - Whether the Splunk Universal Forwarder should be installed or removed.
      - V(present) ensures the forwarder is installed and configured.
      - V(absent) ensures the forwarder is removed from the system.
    type: str
    choices: ['present', 'absent']
    default: present

  version:
    description:
      - Version of Splunk Universal Forwarder to install (e.g., V(10.0.1)).
      - The build number will be automatically looked up from the versions file.
      - Required when O(state=present).
    type: str

  username:
    description:
      - Username for the Splunk admin account.
      - Required when O(state=present).
    type: str

  password:
    description:
      - Password for the Splunk admin account.
      - Required when O(state=present).
    type: str
    no_log: true

notes:
  - This module only works on RHEL 8, 9, and 10 systems.
  - The RPM package will be downloaded to V(/opt) from the official Splunk download site.
  - Splunk Universal Forwarder will be installed to V(/opt/splunkforwarder).
  - Requires root privileges to install/remove packages and start services.
  - The module includes built-in version-to-build mappings for Splunk UF versions 9.0.9 through 10.0.1.
  - When upgrading from a previous version, $SPLUNK_HOME/etc & $SPLUNK_HOME/var directories will be preserved to save previous data.
"""

EXAMPLES = r"""
- name: Install Splunk Universal Forwarder
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    username: admin
    password: "changeme123"

- name: Remove Splunk Universal Forwarder
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: absent

- name: Install Splunk Universal Forwarder (check mode)
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    username: admin
    password: "changeme123"
  check_mode: true
"""

RETURN = r"""
msg:
  description: Human-readable message describing the action taken.
  type: str
  returned: always
  sample: "Splunk Universal Forwarder 10.0.1 installed successfully"

version:
  description: Version of Splunk Universal Forwarder that was installed or removed.
  type: str
  returned: always
  sample: "10.0.1"

build_number:
  description: Build number corresponding to the version.
  type: str
  returned: when state is present
  sample: "c486717c322b"

rpm_path:
  description: Path where the RPM file was downloaded.
  type: str
  returned: when state is present
  sample: "/opt/splunkforwarder-10.0.1-c486717c322b.x86_64.rpm"

splunk_home:
  description: Installation directory of Splunk Universal Forwarder.
  type: str
  returned: always
  sample: "/opt/splunkforwarder"

changed:
  description: Whether any changes were made.
  type: bool
  returned: always
  sample: true
"""


import os
import re
import hashlib
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url


def check_rhel_version(module: AnsibleModule) -> str:
    """Check if the system is RHEL 8, 9, or 10."""
    try:
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                content = f.read()        
            if 'Red Hat Enterprise Linux' not in content and 'RHEL' not in content:
                module.fail_json(msg="This module only supports RHEL systems")
            version_match = re.search(r'VERSION_ID="?(\d+)', content)
            if version_match:
                major_version = version_match.group(1)
                if major_version in ['8', '9', '10']:
                    return major_version
                else:
                    module.fail_json(msg=f"Unsupported RHEL version: {major_version}. Only RHEL 8, 9, and 10 are supported")
            else:
                module.fail_json(msg="Could not determine RHEL version")
        else:
            module.fail_json(msg="/etc/os-release not found. Cannot verify RHEL version")
    except Exception as e:
        module.fail_json(msg=f"Error checking RHEL version: {str(e)}")


def get_versions_map() -> dict:
    """Return the versions to build-number mapping."""
    return {
        "10.0.1": "c486717c322b",
        "10.0.0": "e8eb0c4654f8",
        "9.4.7": "2a9293b80994",
        "9.4.6": "60284236e579",
        "9.4.5": "8fb2a6c586a5",
        "9.4.4": "f627d88b766b",
        "9.4.3": "237ebbd22314",
        "9.4.2": "e9664af3d956",
        "9.4.1": "e3bdab203ac8",
        "9.4.0": "6b4ebe426ca6",
        "9.3.8": "26d4c728325e",
        "9.3.7": "82e666993132",
        "9.3.6": "6320df444747",
        "9.3.5": "37a93798d197",
        "9.3.4": "ec9a1599553c",
        "9.3.3": "7774d8050982",
        "9.3.2": "7486e92e5971",
        "9.3.1": "550742880053",
        "9.3.0": "5449755b46d0",
        "9.2.11": "6c457f00305f",
        "9.2.10": "9f32f38448a5",
        "9.2.9": "8482613309a6",
        "9.2.8": "93f3503f563d",
        "9.2.7": "6df8899806b7",
        "9.2.6": "778553f18e87",
        "9.1.10": "f519446d315b",
        "9.1.9": "301569426f4a",
        "9.1.8": "648a8677f15b",
        "9.1.7": "e17104057ef0",
        "9.1.6": "a28f08fac354",
        "9.1.5": "29befd543def",
        "9.1.4": "a414fc70250e",
        "9.0.10": "099a46979944",
        "9.0.9": "249852267605",
    }


def get_build_number(module: AnsibleModule, versions: dict, version: str) -> str:
    """Get the build number for a specific version."""
    if version not in versions:
        available = ', '.join(sorted(versions.keys(), reverse=True))
        module.fail_json(msg=f"Version {version} not found. Available versions: {available}")
    return versions[version]


def is_splunk_installed(module: AnsibleModule) -> bool:
    """Check if Splunk Universal Forwarder is already installed using RPM."""
    rc, out, err = module.run_command(['rpm', '-qa', 'splunkforwarder'])
    return rc == 0 and 'splunkforwarder' in out


def get_installed_version(module: AnsibleModule) -> str | None:
    """Get the currently installed Splunk version from RPM."""
    if not is_splunk_installed(module):
        return None
    try:
        rc, out, err = module.run_command(['rpm', '-q', '--queryformat', '%{VERSION}', 'splunkforwarder'])
        if rc == 0 and out:
            return out.strip()
        return None
    except Exception:
        return None


def download_file(module: AnsibleModule, url: str, dest_path: str) -> None:
    """Download a file from URL to destination path."""
    if module.check_mode:
        return
    try:
        response = open_url(url, timeout=300)
        with open(dest_path, 'wb') as f:
            f.write(response.read())
    except Exception as e:
        module.fail_json(msg=f"Failed to download {url}: {str(e)}")


def verify_checksum(module: AnsibleModule, rpm_path: str, checksum_path: str) -> bool:
    """Verify the RPM file against SHA512 checksum."""
    try:
        with open(checksum_path, 'r') as f:
            checksum_content = f.read().strip()
        checksum_match = re.search(r'SHA512\([^)]+\)=\s*([a-fA-F0-9]+)', checksum_content)
        if not checksum_match:
            module.fail_json(msg=f"Could not parse checksum file: {checksum_path}")
        expected_checksum = checksum_match.group(1).lower()
        sha512 = hashlib.sha512()
        with open(rpm_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha512.update(chunk)
        actual_checksum = sha512.hexdigest()
        if actual_checksum != expected_checksum:
            module.fail_json(
                msg=f"Checksum verification failed for {rpm_path}. "
                    f"Expected: {expected_checksum}, Got: {actual_checksum}"
            )
        return True
    except Exception as e:
        module.fail_json(msg=f"Error verifying checksum: {str(e)}")


def install_rpm(module: AnsibleModule, rpm_path: str) -> tuple[int, str, str]:
    """Install the RPM package."""
    if module.check_mode:
        return 0, "Check mode: would install RPM", ""
    rc, out, err = module.run_command(['rpm', '-i', rpm_path])
    return rc, out, err


def remove_rpm(module: AnsibleModule, package_name: str) -> tuple[int, str, str]:
    """Remove the RPM package."""
    if module.check_mode:
        return 0, "Check mode: would remove RPM", ""
    rc, out, err = module.run_command(['rpm', '-e', package_name])
    return rc, out, err


def create_user_seed_conf(module: AnsibleModule, splunk_home: str, username: str, password: str) -> None:
    """Create the user-seed.conf file with admin credentials."""
    if module.check_mode:
        return
    local_dir = os.path.join(splunk_home, 'etc', 'system', 'local')
    user_seed_path = os.path.join(local_dir, 'user-seed.conf')
    try:
        os.makedirs(local_dir, exist_ok=True)
    except Exception as e:
        module.fail_json(msg=f"Failed to create directory {local_dir}: {str(e)}")
    try:
        with open(user_seed_path, 'w') as f:
            f.write('[user_info]\n')
            f.write(f'USERNAME = {username}\n')
            f.write(f'PASSWORD = {password}\n')
        os.chmod(user_seed_path, 0o600)
    except Exception as e:
        module.fail_json(msg=f"Failed to create user-seed.conf: {str(e)}")


def start_splunk(module: AnsibleModule, splunk_home: str) -> tuple[int, str, str]:
    """Start Splunk for the first time with license acceptance."""
    if module.check_mode:
        return 0, "Check mode: would start Splunk", ""
    splunk_bin = os.path.join(splunk_home, 'bin', 'splunk')
    env = os.environ.copy()
    env['SPLUNK_HOME'] = splunk_home
    rc, out, err = module.run_command(
        [splunk_bin, 'start', '--accept-license', '--answer-yes'],
        environ_update=env
    )
    if not check_splunk_service(module, splunk_home, 'start'):
        module.fail_json(msg="Failed to start Splunk service")
    return rc, out, err


def enable_systemd_service(module: AnsibleModule, splunk_home: str) -> tuple[int, str, str]:
    """Enable and start the SplunkForwarder systemd service using Splunk commands."""
    if module.check_mode:
        return 0, "Check mode: would enable/start SplunkForwarder systemd service", ""    
    
    splunk_bin = os.path.join(splunk_home, 'bin', 'splunk')
    
    rc, out, err = module.run_command([splunk_bin, 'stop'], check_rc=False)
    if rc != 0:
        module.fail_json(msg=f"Failed to stop Splunk: {err}")
    if check_splunk_service(module, splunk_home, 'stop'):
        module.log("Splunk service stopped successfully")
    else:
        module.fail_json(msg="Failed to stop Splunk service")
    
    rc, out, err = module.run_command([splunk_bin, 'disable', 'boot-start'], check_rc=False)
    if rc != 0:
        module.fail_json(msg=f"Failed to disable boot-start: {err}")
    
    rc, out, err = module.run_command([splunk_bin, 'enable', 'boot-start'])
    if rc != 0:
        module.fail_json(msg=f"Failed to enable boot-start: {err}")
    
    rc, out, err = module.run_command([splunk_bin, 'start'])
    if rc != 0:
        module.fail_json(msg="Failed to start Splunk")
    if check_splunk_service(module, splunk_home, 'start'):
        module.log("Splunk service started successfully")
    else:
        module.fail_json(msg="Failed to start Splunk service")
    return rc, out, err


def check_splunk_service(module: AnsibleModule, splunk_home: str, desired_state: str, max_retries: int = 6, retry_delay: int = 5) -> bool:
    """Check if Splunk service is in the desired state."""
    if module.check_mode:
        return True
    if desired_state not in ['start', 'stop']:
        module.fail_json(msg=f"Invalid desired_state: {desired_state}. Must be 'start' or 'stop'")
    splunk_bin = os.path.join(splunk_home, 'bin', 'splunk')
    for attempt in range(1, max_retries + 1):
        rc, out, err = module.run_command([splunk_bin, 'status'], check_rc=False)
        if desired_state == 'start' and rc == 0:
            module.log(f"Splunk service verified as running (attempt {attempt}/{max_retries})")
            return True
        elif desired_state == 'stop' and rc == 3:
            module.log(f"Splunk service verified as stopped (attempt {attempt}/{max_retries})")
            return True
        # Retry
        if attempt < max_retries:
            module.log(f"Splunk not yet in desired state '{desired_state}', retrying in {retry_delay}s (attempt {attempt}/{max_retries})")
            import time
            time.sleep(retry_delay)
    # Max retries exhausted
    module.log(f"Splunk service did not reach desired state '{desired_state}' after {max_retries} attempts (last rc={rc})")
    return False


def uninstall_splunk(module: AnsibleModule, splunk_home: str) -> dict:
    """Uninstall Splunk Universal Forwarder from the system."""
    result = dict(changed=False, msg="Splunk Universal Forwarder is not installed")
    
    if not is_splunk_installed(module):
        return result
    
    if not module.check_mode:
        # Stop Splunk service
        splunk_bin = os.path.join(splunk_home, 'bin', 'splunk')
        if os.path.exists(splunk_bin):
            module.run_command([splunk_bin, 'stop'], check_rc=False)
            # Verify the service stopped
            if check_splunk_service(module, splunk_home, 'stop'):
                module.log("Splunk service stopped successfully")
            else:
                module.fail_json(msg="Failed to stop Splunk service")
        rc, out, err = module.run_command([splunk_bin, 'disable', 'boot-start'], check_rc=False)
        if rc != 0:
            module.fail_json(msg=f"Failed to disable boot-start: {err}")
    # Remove the RPM package
    rc, out, err = remove_rpm(module, 'splunkforwarder')
    if rc != 0 and 'not installed' not in err.lower():
        module.fail_json(msg=f"Failed to remove Splunk Universal Forwarder: {err}", stdout=out, stderr=err)
    
    if not module.check_mode:
        systemd_files = [
            '/usr/lib/systemd/system/SplunkForwarder.service',
            '/etc/systemd/system/SplunkForwarder.service',
            '/etc/systemd/system/multi-user.target.wants/SplunkForwarder.service',
        ]
        for service_file in systemd_files:
            if os.path.exists(service_file):
                try:
                    os.remove(service_file)
                    module.log(f"Removed systemd file: {service_file}")
                except Exception as e:
                    module.warn(f"Failed to remove {service_file}: {str(e)}")
        
        # Reload systemd and reset failed services
        module.run_command(['systemctl', 'daemon-reload'], check_rc=False)
        module.run_command(['systemctl', 'reset-failed'], check_rc=False)
    
    result['changed'] = True
    result['msg'] = "Splunk Universal Forwarder removed successfully"
    return result


def main() -> None:
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            version=dict(type='str'),
            username=dict(type='str'),
            password=dict(type='str', no_log=True),
        ),
        required_if=[
            ('state', 'present', ['version', 'username', 'password']),
        ],
        supports_check_mode=True,
    )

    state = module.params['state']
    version = module.params['version']
    username = module.params['username']
    password = module.params['password']
    download_dir = '/opt'
    splunk_home = '/opt/splunkforwarder'

    # Check RHEL version
    rhel_version = check_rhel_version(module)
    module.log(f"RHEL version: {rhel_version}")

    result = dict(
        changed=False,
        version=version,
        splunk_home=splunk_home,
    )

    # Handle removal (state == 'absent')
    if state == 'absent':
        removal_result = uninstall_splunk(module, splunk_home)
        result.update(removal_result)
        module.exit_json(**result)

    # Handle installation (state == 'present')
    versions = get_versions_map()
    build_number = get_build_number(module, versions, version)
    result['build_number'] = build_number

    # Check if already installed with correct version
    installed_version = get_installed_version(module)
    if installed_version == version:
        result['msg'] = f"Splunk Universal Forwarder {version} is already installed"
        module.exit_json(**result)

    rpm_filename = f"splunkforwarder-{version}-{build_number}.x86_64.rpm"
    rpm_url = f"https://download.splunk.com/products/universalforwarder/releases/{version}/linux/{rpm_filename}"
    checksum_url = f"{rpm_url}.sha512"
    
    rpm_path = os.path.join(download_dir, rpm_filename)
    checksum_path = f"{rpm_path}.sha512"
    
    result['rpm_path'] = rpm_path

    if not os.path.exists(rpm_path) or not os.path.exists(checksum_path):
        if not module.check_mode:
            module.log(f"Downloading RPM from {rpm_url}")
            download_file(module, rpm_url, rpm_path)
            
            module.log(f"Downloading checksum from {checksum_url}")
            download_file(module, checksum_url, checksum_path)

    if not module.check_mode:
        module.log("Verifying RPM checksum")
        verify_checksum(module, rpm_path, checksum_path)

    if installed_version:
        module.log(f"Uninstalling old Splunk Universal Forwarder {installed_version}")
        uninstall_result = uninstall_splunk(module, splunk_home)
        module.log(f"Uninstall result: {uninstall_result['msg']}")

    module.log(f"Installing Splunk Universal Forwarder {version}")
    rc, out, err = install_rpm(module, rpm_path)

    if rc != 0:
        module.fail_json(msg=f"Failed to install RPM: {err}", stdout=out, stderr=err)

    if not module.check_mode:
        os.environ['SPLUNK_HOME'] = splunk_home

    # Create user-seed.conf
    passwd_path = os.path.join(splunk_home, 'etc', 'passwd')
    if not os.path.exists(passwd_path):
        module.log("Creating user-seed.conf")
        create_user_seed_conf(module, splunk_home, username, password)

    # Start Splunk for the first time
    module.log("Starting Splunk Universal Forwarder")
    rc, out, err = start_splunk(module, splunk_home)
    if rc != 0:
        module.warn(f"Splunk start returned non-zero exit code: {err}")

    # Enable and start the SplunkForwarder systemd service
    module.log("Enabling and starting SplunkForwarder systemd service")
    rc, out, err = enable_systemd_service(module, splunk_home)
    if rc != 0:
        module.warn(f"Failed to enable/start SplunkForwarder systemd service: {err}")

    result['changed'] = True
    result['msg'] = f"Splunk Universal Forwarder {version} installed and started successfully"

    module.exit_json(**result)


if __name__ == '__main__':
    main()
