#!/usr/bin/python

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
module: splunk_universal_forwarder_linux_info

short_description: Gather information about Splunk Universal Forwarder installations on RHEL systems

description:
  - This module gathers information about Splunk Universal Forwarder installations on RHEL 8, 9, and 10 systems.
  - Returns installation state, version, release id, CPU architecture, forward servers, and deployment server configuration.

version_added: "1.0.0"

author:
  - Shahar Golshani (@shahargolshani)

options:
  username:
    description:
      - Username for the Splunk admin account.
      - Required to retrieve forward_servers information.
    type: str
    required: true

  password:
    description:
      - Password for the Splunk admin account.
      - Required to retrieve forward_servers information.
    type: str
    required: true

notes:
  - This module only works on RHEL 8, 9, and 10 systems.
  - Splunk Universal Forwarder is expected to be installed in V(/opt/splunkforwarder) with RPM package.
  - Requires the Splunk service to be running to retrieve forward_servers information.
"""

EXAMPLES = r"""
- name: Gather Splunk Universal Forwarder information
  splunk.enterprise.splunk_universal_forwarder_linux_info:
    username: admin
    password: "password"
  register: splunk_info

- name: Display Splunk information
  ansible.builtin.debug:
    var: splunk_info

- name: Check if Splunk is installed
  splunk.enterprise.splunk_universal_forwarder_linux_info:
    username: admin
    password: "password"
  register: splunk_info

- name: Show message if not installed
  ansible.builtin.debug:
    msg: "Splunk Universal Forwarder is not installed"
  when: splunk_info.state == 'absent'
"""

RETURN = r"""
state:
  description: Whether the Splunk Universal Forwarder is installed.
  type: str
  returned: always
  sample: "present"
  choices: ['present', 'absent']

version:
  description: Version of Splunk Universal Forwarder that is installed.
  type: str
  returned: when state is present
  sample: "10.0.1"

release_id:
  description: Release id corresponding to the installed version.
  type: str
  returned: when state is present
  sample: "c486717c322b"

cpu:
  description: CPU architecture of the installed package.
  type: str
  returned: when state is present
  sample: "x86_64"

forward_servers:
  description: List of configured forward servers. Empty list if none configured.
  type: list
  elements: str
  returned: when state is present
  sample: ["splunk-indexer1.example.com:9997", "192.168.1.100:9997"]

deployment_server:
  description: Configured deployment server URI. Empty string if not configured.
  type: str
  returned: when state is present
  sample: "deployment-server.example.com:8089"

splunk_home:
  description: Installation directory of Splunk Universal Forwarder.
  type: str
  returned: always
  sample: "/opt/splunkforwarder"

rhel_version:
  description: Major version of RHEL on the system.
  type: str
  returned: always
  sample: "9"
"""


import os
import re

from ansible.module_utils.basic import AnsibleModule


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


def get_installed_release_id(module: AnsibleModule):
    """Get the currently installed Splunk release id from RPM RELEASE field."""
    if not is_splunk_installed(module):
        return None
    try:
        rc, out, err = module.run_command(
            ["rpm", "-q", "--queryformat", "%{RELEASE}", "splunkforwarder"],
        )
        if rc == 0 and out:
            return out.strip()
        return None
    except Exception:
        return None


def get_installed_cpu_arch(module: AnsibleModule):
    """Get the CPU architecture of the installed Splunk package from RPM."""
    if not is_splunk_installed(module):
        return None
    try:
        rc, out, err = module.run_command(
            ["rpm", "-q", "--queryformat", "%{ARCH}", "splunkforwarder"],
        )
        if rc == 0 and out:
            return out.strip()
        return None
    except Exception:
        return None


def get_forward_servers(
    module: AnsibleModule,
    splunk_home: str,
    username: str,
    password: str,
) -> list:
    """Get list of existing forward-servers from the Splunk Universal Forwarder."""
    splunk_bin = os.path.join(splunk_home, "bin", "splunk")
    if not os.path.exists(splunk_bin):
        return []
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
    forward_servers = []
    current_key = None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            current_key = line.replace(":", "")
        elif current_key:
            if line.lower() != "none":
                forward_servers.append(line)
    return forward_servers


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


def main() -> None:
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(type="str", required=True),
            password=dict(type="str", no_log=True, required=True),
        ),
        supports_check_mode=True,
    )

    username = module.params["username"]
    password = module.params["password"]
    splunk_home = "/opt/splunkforwarder"

    rhel_version = check_rhel_version(module)

    result = dict(
        changed=False,
        splunk_home=splunk_home,
        rhel_version=rhel_version,
    )

    if not is_splunk_installed(module):
        result["state"] = "absent"
        module.exit_json(**result)

    result["state"] = "present"

    version = get_installed_version(module)
    if version:
        result["version"] = version

    release_id = get_installed_release_id(module)
    if release_id:
        result["release_id"] = release_id

    cpu = get_installed_cpu_arch(module)
    if cpu:
        result["cpu"] = cpu

    forward_servers = get_forward_servers(module, splunk_home, username, password)
    result["forward_servers"] = forward_servers

    deployment_server = get_deployment_server(module, splunk_home)
    result["deployment_server"] = deployment_server if deployment_server else ""

    module.exit_json(**result)


if __name__ == "__main__":
    main()
