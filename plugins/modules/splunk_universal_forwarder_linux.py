#!/usr/bin/python

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: splunk_universal_forwarder_linux

short_description: Manage Splunk Universal Forwarder installations on RHEL systems

description:
  - This module manages Splunk Universal Forwarder installations on RHEL 8, 9, and 10 systems using RPM packages.
  - Downloads the Splunk Universal Forwarder RPM and verifies its integrity using SHA512 checksums.
  - Supports idempotent installation and removal of the forwarder.
  - Automatically configures user credentials and starts the forwarder on first installation.
  - If the forwarder is already installed, only upgrades are allowed.
  - To downgrade the forwarder, you can use 2 tasks - absent then present.
  - Password is set on first installation only, On subsequent tasks the user/password has to be provided.

version_added: "1.0.0"

author:
  - Shahar Golshani (@shahargolshani)

attributes:
  check_mode:
    description: The module supports check mode and will report what changes would be made without actually making them.
    support: full
  diff_mode:
    description: The module does not support diff mode.
    support: none

options:
  state:
    description:
      - Whether the Splunk Universal Forwarder should be installed or removed.
      - V(present) ensures the forwarder is installed and configured.
      - V(absent) ensures the forwarder is removed from the system and all configuration is removed.
    type: str
    choices: ['present', 'absent']
    default: present

  version:
    description:
      - Version of Splunk Universal Forwarder to install (e.g., V(10.0.1)).
      - Required when O(state=present).
    type: str

  release_id:
    description:
      - Release id corresponding to the Splunk Universal Forwarder version (e.g., V(c486717c322b)).
      - The release id can be found on the Splunk download page for each version.
      - Combined with O(version) to form the RPM filename (e.g., V(10.0.1-c486717c322b)).
      - Required when O(state=present).
    type: str

  username:
    description:
      - Username for the Splunk admin account.
      - Required when O(state=present).
      - User Will be craeted on scratch installation.
      - Required to retrieve information on subsequent tasks.
    type: str

  password:
    description:
      - Password for the Splunk admin account.
      - Required when O(state=present).
      - Will be set to this value on scratch installation.
      - Required to retrieve information on subsequent tasks.
    type: str

  cpu:
    description:
      - CPU architecture for the Splunk Universal Forwarder package.
      - V(64-bit) for x86_64 architecture.
      - V(ARM) for aarch64 architecture.
    type: str
    choices: ['64-bit', 'ARM']
    default: 64-bit

  forward_servers:
    description:
      - List of Splunk Enterprise servers to forward data to.
      - Each entry must be in V(<host>:<port>) format (e.g., V(splunk-indexer.example.com:9997)).
      - The default Splunk receiving port is typically V(9997).
      - When specified, configures the forwarder to send data to these servers, Sets the forward-servers exactly to this list.
      - When list is empty, The current configured forward-servers will be removed, and the configuration will be empty.
    type: list
    elements: str

  deployment_server:
    description:
      - The Splunk Deployment Server to register with.
      - Must be in V(<host>:<port>) format (e.g., V(deployment-server.example.com:8089)).
      - The default Splunk deployment server port is V(8089).
      - When specified, configures the forwarder to poll this deployment server for apps and configurations.
      - When set to an empty string, removes the deployment server configuration and restarts the forwarder service.
    type: str

notes:
  - This module only works on RHEL 8, 9, and 10 systems.
  - The RPM package will be downloaded to V(/opt) from the official Splunk download site.
  - Splunk Universal Forwarder will be installed to V(/opt/splunkforwarder).
  - Requires root privileges to install/remove packages and start services.
  - The RPM filename is constructed as V(splunkforwarder-{version}-{release_id}.{cpu_arch}.rpm).
  - When upgrading from a previous version, $SPLUNK_HOME/etc & $SPLUNK_HOME/var directories will be preserved to save previous data.
"""

EXAMPLES = r"""
- name: Install Splunk Universal Forwarder (x86_64)
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    release_id: "c486717c322b"
    username: admin
    password: "changeme123"

- name: Install Splunk Universal Forwarder on ARM architecture, with no forward-servers configured
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    release_id: "c486717c322b"
    cpu: ARM
    username: admin
    password: "changeme123"
    forward_servers: []

- name: Install Splunk Universal Forwarder with forward-servers configuration
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    release_id: "c486717c322b"
    username: admin
    password: "changeme123"
    forward_servers:
      - "splunk-indexer1.example.com:9997"
      - "192.168.1.100:9997"

- name: Install Splunk Universal Forwarder with deployment server
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    release_id: "c486717c322b"
    username: admin
    password: "changeme123"
    deployment_server: "deployment-server.example.com:8089"

- name: Remove deployment server configuration
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    release_id: "c486717c322b"
    username: admin
    password: "changeme123"
    deployment_server: ""

- name: Remove Splunk Universal Forwarder
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: absent

- name: Install Splunk Universal Forwarder (check mode)
  splunk.enterprise.splunk_universal_forwarder_linux:
    state: present
    version: "10.0.1"
    release_id: "c486717c322b"
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
  description: Version of Splunk Universal Forwarder that was installed.
  type: str
  returned: when state is present
  sample: "10.0.1"

release_id:
  description: Release id corresponding to the version.
  type: str
  returned: when state is present
  sample: "c486717c322b"

rpm_path:
  description: Path where the RPM file was downloaded.
  type: str
  returned: when state is present
  sample: "/opt/splunkforwarder-10.0.1-c486717c322b.x86_64.rpm"

cpu_arch:
  description: CPU architecture used for the installation.
  type: str
  returned: when state is present
  sample: "x86_64"

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


import hashlib
import os
import re
import shutil
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url


def check_rhel_version(module: AnsibleModule) -> str:
    """Check if the system is RHEL 8, 9, or 10."""
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                content = f.read()
            if "Red Hat Enterprise Linux" not in content and "RHEL" not in content:
                module.fail_json(msg="This module only supports RHEL systems")
            version_match = re.search(r'VERSION_ID="?(\d+)', content)
            if version_match:
                major_version = version_match.group(1)
                if major_version in ["8", "9", "10"]:
                    return major_version
                else:
                    module.fail_json(
                        msg=f"Unsupported RHEL version: {major_version}. Only RHEL 8, 9, and 10 are supported",
                    )
            else:
                module.fail_json(msg="Could not determine RHEL version")
        else:
            module.fail_json(
                msg="/etc/os-release not found. Cannot verify RHEL version",
            )
    except Exception as e:
        module.fail_json(msg=f"Error checking RHEL version: {str(e)}")


def is_splunk_installed(module: AnsibleModule) -> bool:
    """Check if Splunk Universal Forwarder is already installed using RPM."""
    rc, out, err = module.run_command(["rpm", "-qa", "splunkforwarder"])
    return rc == 0 and "splunkforwarder" in out


def get_installed_version(module: AnsibleModule):
    """Get the currently installed Splunk version from RPM."""
    if not is_splunk_installed(module):
        return None
    try:
        rc, out, err = module.run_command(
            ["rpm", "-q", "--queryformat", "%{VERSION}", "splunkforwarder"],
        )
        if rc == 0 and out:
            return out.strip()
        return None
    except Exception:
        return None


def check_if_downgrade(version_a, version_b):
    """Allow only universal forwarder upgrades, To prevent configuration errors - To downgrade use absent -> present"""
    a = list(map(int, version_a.split(".")))
    b = list(map(int, version_b.split(".")))
    for i in range(3):
        if a[i] > b[i]:
            return True
        if a[i] < b[i]:
            return False
    return False


def download_file(module: AnsibleModule, url: str, dest_path: str) -> None:
    """Download a file from URL to destination path."""
    if module.check_mode:
        return
    try:
        response = open_url(url, timeout=300)
        with open(dest_path, "wb") as f:
            f.write(response.read())
    except Exception as e:
        module.fail_json(msg=f"Failed to download {url}: {str(e)}")


def verify_checksum(module: AnsibleModule, rpm_path: str, checksum_path: str) -> bool:
    """Verify the RPM file against SHA512 checksum."""
    try:
        with open(checksum_path, "r") as f:
            checksum_content = f.read().strip()
        checksum_match = re.search(
            r"SHA512\([^)]+\)=\s*([a-fA-F0-9]+)",
            checksum_content,
        )
        if not checksum_match:
            module.fail_json(msg=f"Could not parse checksum file: {checksum_path}")
        expected_checksum = checksum_match.group(1).lower()
        sha512 = hashlib.sha512()
        with open(rpm_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha512.update(chunk)
        actual_checksum = sha512.hexdigest()
        if actual_checksum != expected_checksum:
            module.fail_json(
                msg=f"Checksum verification failed for {rpm_path}. "
                f"Expected: {expected_checksum}, Got: {actual_checksum}",
            )
        return True
    except Exception as e:
        module.fail_json(msg=f"Error verifying checksum: {str(e)}")


def install_rpm(module: AnsibleModule, rpm_path: str):
    """Install the RPM package."""
    if module.check_mode:
        return 0, "Check mode: would install RPM", ""
    rc, out, err = module.run_command(["rpm", "-i", rpm_path])
    return rc, out, err


def remove_rpm(module: AnsibleModule, package_name: str):
    """Remove the RPM package."""
    if module.check_mode:
        return 0, "Check mode: would remove RPM", ""
    rc, out, err = module.run_command(["rpm", "-e", package_name])
    return rc, out, err


def create_user_seed_conf(
    module: AnsibleModule,
    splunk_home: str,
    username: str,
    password: str,
) -> None:
    """Create the user-seed.conf file with admin credentials."""
    if module.check_mode:
        return
    local_dir = os.path.join(splunk_home, "etc", "system", "local")
    user_seed_path = os.path.join(local_dir, "user-seed.conf")
    try:
        os.makedirs(local_dir, exist_ok=True)
    except Exception as e:
        module.fail_json(msg=f"Failed to create directory {local_dir}: {str(e)}")
    try:
        with open(user_seed_path, "w") as f:
            f.write("[user_info]\n")
            f.write(f"USERNAME = {username}\n")
            f.write(f"PASSWORD = {password}\n")
        os.chmod(user_seed_path, 0o600)
    except Exception as e:
        module.fail_json(msg=f"Failed to create user-seed.conf: {str(e)}")


def get_existing_forward_servers(
    module: AnsibleModule,
    splunk_home: str,
    username: str,
    password: str,
) -> list:
    """Get list of existing forward-servers from the Splunk Universal Forwarder."""
    if module.check_mode:
        return []
    splunk_bin = os.path.join(splunk_home, "bin", "splunk")
    env = os.environ.copy()
    env["SPLUNK_USERNAME"] = username
    env["SPLUNK_PASSWORD"] = password
    rc, out, err = module.run_command(
        [splunk_bin, "list", "forward-server"],
        environ_update=env,
    )
    if rc != 0:
        module.warn(f"Failed to list forward-servers: {err}")
        return []
    existing_forward_servers = []
    current_key = None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            current_key = line.replace(":", "")
        elif current_key:
            if line.lower() != "none":
                existing_forward_servers.append(line)
    return existing_forward_servers


def manage_forward_servers(
    module: AnsibleModule,
    splunk_home: str,
    username: str,
    password: str,
    forward_servers: list,
    action: str,
) -> bool:
    """add/remove forward-servers from the Splunk Universal Forwarder."""
    if module.check_mode:
        return len(forward_servers) > 0
    changed = False
    splunk_bin = os.path.join(splunk_home, "bin", "splunk")
    env = os.environ.copy()
    env["SPLUNK_USERNAME"] = username
    env["SPLUNK_PASSWORD"] = password
    for server in forward_servers:
        rc, out, err = module.run_command(
            [splunk_bin, action, "forward-server", server],
            environ_update=env,
        )
        if rc != 0:
            module.warn(f"Failed to {action} forward-server {server}: {err}")
        else:
            changed = True
    return changed


def get_deployment_server(module: AnsibleModule, splunk_home: str):
    """Get the currently configured deployment server from deploymentclient.conf."""
    deployment_conf = os.path.join(
        splunk_home,
        "etc",
        "system",
        "local",
        "deploymentclient.conf",
    )
    if not os.path.exists(deployment_conf):
        return None
    try:
        with open(deployment_conf, "r") as f:
            content = f.read()
        # Parse targetUri from [target-broker:deploymentServer] section
        match = re.search(r"targetUri\s*=\s*(\S+)", content)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        module.warn(f"Failed to read deploymentclient.conf: {str(e)}")
        return None


def set_deployment_server(
    module: AnsibleModule,
    splunk_home: str,
    username: str,
    password: str,
    deployment_server: str,
) -> bool:
    """Set the deployment server using the Splunk CLI command."""
    if module.check_mode:
        return True
    splunk_bin = os.path.join(splunk_home, "bin", "splunk")
    env = os.environ.copy()
    env["SPLUNK_USERNAME"] = username
    env["SPLUNK_PASSWORD"] = password
    rc, out, err = module.run_command(
        [splunk_bin, "set", "deploy-poll", deployment_server],
        environ_update=env,
    )
    if rc != 0:
        module.warn(f"Failed to set deploy-poll to {deployment_server}: {err}")
        return False
    return True


def remove_deployment_server(module: AnsibleModule, splunk_home: str) -> bool:
    """Remove the deployment server by deleting deploymentclient.conf and restarting Splunk."""
    if module.check_mode:
        return True
    deployment_conf = os.path.join(
        splunk_home,
        "etc",
        "system",
        "local",
        "deploymentclient.conf",
    )
    if os.path.exists(deployment_conf):
        try:
            os.remove(deployment_conf)
            module.log(f"Removed deployment client config: {deployment_conf}")
        except Exception as e:
            module.warn(f"Failed to remove deploymentclient.conf: {str(e)}")
            return False
        # Restart Splunk service to apply changes
        splunk_bin = os.path.join(splunk_home, "bin", "splunk")
        rc, out, err = module.run_command([splunk_bin, "restart"], check_rc=False)
        if rc != 0:
            module.warn(
                f"Failed to restart Splunk after removing deployment server: {err}",
            )
            return False
        if not check_splunk_service(module, splunk_home, "start"):
            module.warn(
                "Splunk service did not restart properly after removing deployment server",
            )
            return False
        return True
    return False


def start_splunk(module: AnsibleModule, splunk_home: str):
    """Start Splunk for the first time with license acceptance."""
    if module.check_mode:
        return 0, "Check mode: would start Splunk", ""
    splunk_bin = os.path.join(splunk_home, "bin", "splunk")
    env = os.environ.copy()
    env["SPLUNK_HOME"] = splunk_home
    rc, out, err = module.run_command(
        [splunk_bin, "start", "--accept-license", "--answer-yes"],
        environ_update=env,
    )
    if not check_splunk_service(module, splunk_home, "start"):
        module.fail_json(msg="Failed to start Splunk service")
    return rc, out, err


def enable_systemd_service(
    module: AnsibleModule,
    splunk_home: str,
):
    """Enable and start the SplunkForwarder systemd service using Splunk commands."""
    if module.check_mode:
        return 0, "Check mode: would enable/start SplunkForwarder systemd service", ""

    splunk_bin = os.path.join(splunk_home, "bin", "splunk")

    rc, out, err = module.run_command([splunk_bin, "stop"], check_rc=False)
    if rc != 0:
        module.fail_json(msg=f"Failed to stop Splunk: {err}")
    if check_splunk_service(module, splunk_home, "stop"):
        module.log("Splunk service stopped successfully")
    else:
        module.fail_json(msg="Failed to stop Splunk service")

    rc, out, err = module.run_command(
        [splunk_bin, "disable", "boot-start"],
        check_rc=False,
    )
    if rc != 0:
        module.fail_json(msg=f"Failed to disable boot-start: {err}")

    rc, out, err = module.run_command([splunk_bin, "enable", "boot-start"])
    if rc != 0:
        module.fail_json(msg=f"Failed to enable boot-start: {err}")

    rc, out, err = module.run_command([splunk_bin, "start"])
    if rc != 0:
        module.fail_json(msg="Failed to start Splunk")
    if check_splunk_service(module, splunk_home, "start"):
        module.log("Splunk service started successfully")
    else:
        module.fail_json(msg="Failed to start Splunk service")
    return rc, out, err


def check_splunk_service(
    module: AnsibleModule,
    splunk_home: str,
    desired_state: str,
    max_retries: int = 6,
    retry_delay: int = 5,
) -> bool:
    """Check if Splunk service is in the desired state."""
    if module.check_mode:
        return True
    if desired_state not in ["start", "stop"]:
        module.fail_json(
            msg=f"Invalid desired_state: {desired_state}. Must be 'start' or 'stop'",
        )
    splunk_bin = os.path.join(splunk_home, "bin", "splunk")
    for attempt in range(1, max_retries + 1):
        rc, out, err = module.run_command([splunk_bin, "status"], check_rc=False)
        if desired_state == "start" and rc == 0:
            module.log(
                f"Splunk service verified as running (attempt {attempt}/{max_retries})",
            )
            return True
        elif desired_state == "stop" and rc == 3:
            module.log(
                f"Splunk service verified as stopped (attempt {attempt}/{max_retries})",
            )
            return True
        # Retry
        if attempt < max_retries:
            module.log(
                f"Splunk not yet in desired state '{desired_state}', retrying in {retry_delay}s (attempt {attempt}/{max_retries})",
            )
            import time

            time.sleep(retry_delay)
    # Max retries exhausted
    module.log(
        f"Splunk service did not reach desired state '{desired_state}' after {max_retries} attempts (last rc={rc})",
    )
    return False


def uninstall_splunk(module: AnsibleModule, splunk_home: str) -> dict:
    """Uninstall Splunk Universal Forwarder from the system."""
    result = dict(changed=False, msg="Splunk Universal Forwarder is not installed")

    if not is_splunk_installed(module):
        return result

    if not module.check_mode:
        # Stop Splunk service
        splunk_bin = os.path.join(splunk_home, "bin", "splunk")
        if os.path.exists(splunk_bin):
            module.run_command([splunk_bin, "stop"], check_rc=False)
            # Verify the service stopped
            if check_splunk_service(module, splunk_home, "stop"):
                module.log("Splunk service stopped successfully")
            else:
                module.fail_json(msg="Failed to stop Splunk service")
        rc, out, err = module.run_command(
            [splunk_bin, "disable", "boot-start"],
            check_rc=False,
        )
        if rc != 0:
            module.fail_json(msg=f"Failed to disable boot-start: {err}")
    # Remove the RPM package
    rc, out, err = remove_rpm(module, "splunkforwarder")
    if rc != 0 and "not installed" not in err.lower():
        module.fail_json(
            msg=f"Failed to remove Splunk Universal Forwarder: {err}",
            stdout=out,
            stderr=err,
        )

    if not module.check_mode:
        systemd_files = [
            "/usr/lib/systemd/system/SplunkForwarder.service",
            "/etc/systemd/system/SplunkForwarder.service",
            "/etc/systemd/system/multi-user.target.wants/SplunkForwarder.service",
        ]
        for service_file in systemd_files:
            if os.path.exists(service_file):
                try:
                    os.remove(service_file)
                    module.log(f"Removed systemd file: {service_file}")
                except Exception as e:
                    module.warn(f"Failed to remove {service_file}: {str(e)}")

        # Reload systemd and reset failed services
        module.run_command(["systemctl", "daemon-reload"], check_rc=False)
        module.run_command(["systemctl", "reset-failed"], check_rc=False)

    result["changed"] = True
    result["msg"] = "Splunk Universal Forwarder removed successfully"
    return result


def purge_splunk_home(module: AnsibleModule, splunk_home: str) -> None:
    """Purge the Splunk Universal Forwarder home directory."""
    if not module.check_mode:
        # Safety check: ensure 'splunk' is in {splunk_home} to prevent deletion of system folders!
        if "splunk" not in splunk_home.lower():
            module.fail_json(
                msg=(
                    "To prevent accidental data loss, the deletion process is restricted "
                    f"to directories containing the keyword 'splunk' in their path: {splunk_home}"
                ),
            )
        path = Path(splunk_home)
        if path.exists() and path.is_dir():
            shutil.rmtree(path)
            module.log(f"Removed: {splunk_home}")
        else:
            module.log(f"Directory does not exist or is not a directory: {splunk_home}")


def main() -> None:
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            version=dict(type="str"),
            release_id=dict(type="str"),
            cpu=dict(type="str", default="64-bit", choices=["64-bit", "ARM"]),
            username=dict(type="str"),
            password=dict(type="str", no_log=True),
            forward_servers=dict(type="list", elements="str"),
            deployment_server=dict(type="str"),
        ),
        required_if=[
            ("state", "present", ["version", "release_id", "username", "password"]),
        ],
        supports_check_mode=True,
    )

    state = module.params["state"]
    version = module.params["version"]
    release_id = module.params["release_id"]
    cpu = module.params["cpu"]
    username = module.params["username"]
    password = module.params["password"]
    forward_servers = module.params["forward_servers"]
    deployment_server = module.params["deployment_server"]
    download_dir = "/opt"
    splunk_home = "/opt/splunkforwarder"

    # Map user-friendly CPU names to architecture strings
    cpu_arch_map = {
        "64-bit": "x86_64",
        "ARM": "aarch64",
    }
    cpu_arch = cpu_arch_map[cpu]

    # Check RHEL version
    rhel_version = check_rhel_version(module)
    module.log(f"RHEL version: {rhel_version}")

    result = dict(
        changed=False,
        splunk_home=splunk_home,
    )

    # Handle removal (state == 'absent')
    if state == "absent":
        removal_result = uninstall_splunk(module, splunk_home)
        purge_splunk_home(module, splunk_home)
        result.update(removal_result)
        module.exit_json(**result)

    # Handle installation (state == 'present')
    result["version"] = version
    result["release_id"] = release_id
    result["cpu_arch"] = cpu_arch

    to_add = []
    to_remove = []

    installed_version = get_installed_version(module)

    if installed_version:
        if check_if_downgrade(installed_version, version):
            result["failed"] = True
            result["msg"] = (
                f"Installed Version {installed_version} is newer than {version} "
                "Only universal forwarder upgrades are allowed. "
                "To downgrade use absent -> present."
            )
            module.exit_json(**result)

    if installed_version and forward_servers is not None:
        existing_forward_servers = get_existing_forward_servers(
            module,
            splunk_home,
            username,
            password,
        )
        existing_forward_servers_set = set(existing_forward_servers)
        forward_servers_set = set(forward_servers)
        to_add = list(forward_servers_set - existing_forward_servers_set)
        to_remove = list(existing_forward_servers_set - forward_servers_set)

    if installed_version == version:
        result["msg"] = f"Splunk Universal Forwarder {version} is already installed"
        if to_add:
            if manage_forward_servers(
                module,
                splunk_home,
                username,
                password,
                to_add,
                action="add",
            ):
                result["changed"] = True
            result["msg"] = (
                f"Splunk Universal Forwarder {version} is already installed - forward-servers set: {forward_servers}"
            )
        if to_remove:
            if manage_forward_servers(
                module,
                splunk_home,
                username,
                password,
                to_remove,
                action="remove",
            ):
                result["changed"] = True
            result["msg"] = (
                f"Splunk Universal Forwarder {version} is already installed - forward-servers set: {forward_servers}"
            )
        # Check and configure deployment server if specified
        if deployment_server is not None:
            current_deployment_server = get_deployment_server(module, splunk_home)
            if deployment_server == "":
                # Empty string means remove deployment server
                if current_deployment_server is not None:
                    if remove_deployment_server(module, splunk_home):
                        result["changed"] = True
                        result["msg"] = (
                            f"Splunk Universal Forwarder {version} is already installed - deployment server removed"
                        )
            elif current_deployment_server != deployment_server:
                if set_deployment_server(
                    module,
                    splunk_home,
                    username,
                    password,
                    deployment_server,
                ):
                    result["changed"] = True
                    result["msg"] = (
                        f"Splunk Universal Forwarder {version} is already installed - deployment server set to: {deployment_server}"
                    )
        module.exit_json(**result)

    rpm_filename = f"splunkforwarder-{version}-{release_id}.{cpu_arch}.rpm"
    rpm_url = f"https://download.splunk.com/products/universalforwarder/releases/{version}/linux/{rpm_filename}"
    checksum_url = f"{rpm_url}.sha512"

    rpm_path = os.path.join(download_dir, rpm_filename)
    checksum_path = f"{rpm_path}.sha512"

    result["rpm_path"] = rpm_path

    if not os.path.exists(rpm_path) or not os.path.exists(checksum_path):
        if not module.check_mode:
            module.log(f"Downloading RPM from {rpm_url}")
            download_file(module, rpm_url, rpm_path)

            module.log(f"Downloading checksum from {checksum_url}")
            download_file(module, checksum_url, checksum_path)

    if not module.check_mode:
        module.log("Verifying RPM checksum")
        verify_checksum(module, rpm_path, checksum_path)

    # Uninstall The Previous Splunk Universal Forwarder
    if installed_version:
        module.log(f"Uninstalling old Splunk Universal Forwarder {installed_version}")
        uninstall_result = uninstall_splunk(module, splunk_home)
        module.log(f"Uninstall result: {uninstall_result['msg']}")

    # Install Splunk Universal Forwarder RPM
    module.log(f"Installing Splunk Universal Forwarder {version}")
    rc, out, err = install_rpm(module, rpm_path)
    if rc != 0:
        module.fail_json(msg=f"Failed to install RPM: {err}", stdout=out, stderr=err)

    if not module.check_mode:
        os.environ["SPLUNK_HOME"] = splunk_home

    # Create user-seed.conf
    passwd_path = os.path.join(splunk_home, "etc", "passwd")
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

    # Add forward-servers
    if forward_servers and not installed_version:
        manage_forward_servers(
            module,
            splunk_home,
            username,
            password,
            forward_servers,
            action="add",
        )
    elif forward_servers and installed_version:
        if to_add:
            manage_forward_servers(
                module,
                splunk_home,
                username,
                password,
                to_add,
                action="add",
            )
        if to_remove:
            manage_forward_servers(
                module,
                splunk_home,
                username,
                password,
                to_remove,
                action="remove",
            )

    # Configure deployment server if specified
    if deployment_server is not None:
        current_deployment_server = get_deployment_server(module, splunk_home)
        if deployment_server == "":
            # Empty string means remove deployment server
            if current_deployment_server is not None:
                remove_deployment_server(module, splunk_home)
        elif current_deployment_server != deployment_server:
            set_deployment_server(
                module,
                splunk_home,
                username,
                password,
                deployment_server,
            )

    result["changed"] = True
    result["msg"] = (
        f"Splunk Universal Forwarder {version} installed and started successfully"
    )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
