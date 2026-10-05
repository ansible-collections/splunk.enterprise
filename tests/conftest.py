# Copyright: (c) 2025, splunk.enterprise contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pytest configuration for Ansible collection unit tests.

This file adds the project root to sys.path so that tests can import
from the plugins directory using absolute imports like:
    from plugins.modules.splunk_universal_forwarder_linux import ...
"""

import sys
from pathlib import Path

# Add the project root (parent of tests/) to sys.path
# This allows imports like: from plugins.modules.module_name import ...
projectRoot = Path(__file__).resolve().parent.parent
if str(projectRoot) not in sys.path:
    sys.path.insert(0, str(projectRoot))
