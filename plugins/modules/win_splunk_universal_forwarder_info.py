#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, splunk.enterprise contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: win_splunk_universal_forwarder_info
short_description: Gather information about Splunk Universal Forwarder on Windows
description:
  - Retrieves information about the installed Splunk Universal Forwarder.
  - Returns installation state, version, release ID, forward servers, deployment server, and installation directory.
  - Uses C(splunk.exe) commands authenticated via environment variables to retrieve configuration details.
version_added: "1.0.0"
options:
  username:
    description:
      - Username for the Splunk admin account.
      - Required to retrieve forward_servers and deployment_server information.
    type: str
    required: true
  password:
    description:
      - Password for the Splunk admin account.
      - Required to retrieve forward_servers and deployment_server information.
    type: str
    required: true
  install_dir:
    description:
      - Installation directory of Splunk Universal Forwarder.
      - Used for version detection and running C(splunk.exe) commands.
      - If Splunk was installed to a non-default directory, you MUST provide the same install_dir value.
    type: path
    default: C:\Program Files\SplunkUniversalForwarder
notes:
  - This module is implemented in PowerShell and is intended for use with Windows hosts.
  - The module requires valid Splunk credentials to retrieve forward_servers and deployment_server information.
  - If the Splunk Universal Forwarder is not installed, only C(state) and C(splunk_home) will be returned.
author:
  - Ron Gershburg (@rgershbu)
"""

EXAMPLES = r"""
- name: Gather Splunk Universal Forwarder info
  splunk.enterprise.win_splunk_universal_forwarder_info:
    username: "SplunkAdmin"
    password: "Ch@ng3d!"
  register: splunk_info
- name: Gather info with custom installation directory
  splunk.enterprise.win_splunk_universal_forwarder_info:
    username: "SplunkAdmin"
    password: "Ch@ng3d!"
    install_dir: "D:\\Splunk\\UniversalForwarder"
  register: splunk_info
- name: Check if Splunk is installed
  splunk.enterprise.win_splunk_universal_forwarder_info:
    username: "SplunkAdmin"
    password: "Ch@ng3d!"
  register: splunk_info
- name: Show configured forward servers
  ansible.builtin.debug:
    msg: "Forward servers: {{ splunk_info.forward_servers }}"
  when: splunk_info.state == 'present'
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
  description: Release ID corresponding to the installed version.
  type: str
  returned: when state is present
  sample: "c486717c322b"
forward_servers:
  description: List of configured forward servers.
  type: list
  elements: str
  returned: when state is present
  sample: ["splunk-indexer1.example.com:9997", "192.168.60.60:9997"]
deployment_server:
  description: Configured deployment server URI.
  type: str
  returned: when state is present and deployment server is configured
  sample: "deployment-server.example.com:8089"
splunk_home:
  description: Installation directory of Splunk Universal Forwarder.
  type: str
  returned: always
  sample: "C:\\Program Files\\SplunkUniversalForwarder"
service:
  description: SplunkForwarder service details.
  type: dict
  returned: when state is present
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
"""
