# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock, mock_open, patch

import pytest

from plugins.modules.splunk_universal_forwarder_linux import (
    check_if_downgrade,
    check_rhel_version,
    check_splunk_service,
    get_deployment_server,
    get_existing_forward_servers,
    get_installed_version,
    is_splunk_installed,
)


@pytest.fixture
def mock_module():
    """Create a mock AnsibleModule for testing.

    The fail_json mock raises SystemExit to simulate real Ansible behavior
    where fail_json terminates module execution.
    """
    mock = MagicMock()
    mock.fail_json = MagicMock(side_effect=SystemExit(1))
    mock.warn = MagicMock()
    return mock


# ============================================================================
# Tests for check_rhel_version
# ============================================================================


def test_check_rhel_version_rhel8(mock_module):
    """Test successful detection of RHEL 8."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="8.9"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "8"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_rhel9(mock_module):
    """Test successful detection of RHEL 9."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="9.3"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "9"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_rhel10(mock_module):
    """Test successful detection of RHEL 10."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="10"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "10"
    mock_module.fail_json.assert_not_called()


def test_check_rhel_version_not_rhel(mock_module):
    """Test failure when system is not RHEL."""
    fake_content = 'NAME="Ubuntu"\nVERSION_ID="22.04"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "only supports RHEL" in mock_module.fail_json.call_args[1]["msg"]


def test_check_rhel_version_unsupported_version(mock_module):
    """Test failure when RHEL version is not 8, 9, or 10."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="7.9"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "Unsupported RHEL version" in mock_module.fail_json.call_args[1]["msg"]


def test_check_rhel_version_no_os_release(mock_module):
    """Test failure when /etc/os-release does not exist."""
    with patch("os.path.exists", return_value=False):
        with pytest.raises(SystemExit):
            check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert "/etc/os-release not found" in mock_module.fail_json.call_args[1]["msg"]


def test_check_rhel_version_no_version_id(mock_module):
    """Test failure when VERSION_ID is missing from os-release."""
    fake_content = 'NAME="Red Hat Enterprise Linux"\nPRETTY_NAME="RHEL"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            with pytest.raises(SystemExit):
                check_rhel_version(mock_module)

    mock_module.fail_json.assert_called_once()
    assert (
        "Could not determine RHEL version" in mock_module.fail_json.call_args[1]["msg"]
    )


def test_check_rhel_version_with_rhel_in_name(mock_module):
    """Test successful detection when 'RHEL' is in content."""
    fake_content = 'NAME="RHEL"\nVERSION_ID="9"'

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = check_rhel_version(mock_module)

    assert result == "9"
    mock_module.fail_json.assert_not_called()


# ============================================================================
# Tests for is_splunk_installed
# ============================================================================


def test_is_splunk_installed_true(mock_module):
    """Test when Splunk is installed."""
    mock_module.run_command.return_value = (0, "splunkforwarder-10.0.0-1234.x86_64", "")

    result = is_splunk_installed(mock_module)

    assert result is True
    mock_module.run_command.assert_called_once_with(["rpm", "-qa", "splunkforwarder"])


def test_is_splunk_installed_false_not_found(mock_module):
    """Test when Splunk is not installed (package not found)."""
    mock_module.run_command.return_value = (1, "", "error")

    result = is_splunk_installed(mock_module)

    assert result is False


def test_is_splunk_installed_false_empty_output(mock_module):
    """Test when rpm returns success but empty output."""
    mock_module.run_command.return_value = (0, "", "")

    result = is_splunk_installed(mock_module)

    assert result is False


def test_is_splunk_installed_false_wrong_package(mock_module):
    """Test when output doesn't contain splunkforwarder."""
    mock_module.run_command.return_value = (0, "some-other-package-1.0.0", "")

    result = is_splunk_installed(mock_module)

    assert result is False


# ============================================================================
# Tests for get_installed_version
# ============================================================================


def test_get_installed_version_success(mock_module):
    """Test successful version retrieval."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (0, "10.0.0", "")
        result = get_installed_version(mock_module)

    assert result == "10.0.0"


def test_get_installed_version_not_installed(mock_module):
    """Test when Splunk is not installed."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=False,
    ):
        result = get_installed_version(mock_module)

    assert result is None
    mock_module.run_command.assert_not_called()


def test_get_installed_version_rpm_fails(mock_module):
    """Test when rpm query fails."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (1, "", "error")
        result = get_installed_version(mock_module)

    assert result is None


def test_get_installed_version_empty_output(mock_module):
    """Test when rpm returns empty output."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (0, "", "")
        result = get_installed_version(mock_module)

    assert result is None


def test_get_installed_version_strips_whitespace(mock_module):
    """Test that version output is stripped of whitespace."""
    with patch(
        "plugins.modules.splunk_universal_forwarder_linux.is_splunk_installed",
        return_value=True,
    ):
        mock_module.run_command.return_value = (0, "  10.0.0  \n", "")
        result = get_installed_version(mock_module)

    assert result == "10.0.0"


# ============================================================================
# Tests for check_if_downgrade
# ============================================================================


def test_check_if_downgrade_major_downgrade():
    """Test downgrade detection when major version is lower."""
    result = check_if_downgrade("10.0.0", "9.0.0")
    assert result is True


def test_check_if_downgrade_minor_downgrade():
    """Test downgrade detection when minor version is lower."""
    result = check_if_downgrade("10.2.0", "10.1.0")
    assert result is True


def test_check_if_downgrade_patch_downgrade():
    """Test downgrade detection when patch version is lower."""
    result = check_if_downgrade("10.0.2", "10.0.1")
    assert result is True


def test_check_if_downgrade_major_upgrade():
    """Test upgrade detection when major version is higher."""
    result = check_if_downgrade("9.0.0", "10.0.0")
    assert result is False


def test_check_if_downgrade_minor_upgrade():
    """Test upgrade detection when minor version is higher."""
    result = check_if_downgrade("10.0.0", "10.1.0")
    assert result is False


def test_check_if_downgrade_patch_upgrade():
    """Test upgrade detection when patch version is higher."""
    result = check_if_downgrade("10.0.0", "10.0.1")
    assert result is False


def test_check_if_downgrade_same_version():
    """Test when both versions are identical."""
    result = check_if_downgrade("10.0.0", "10.0.0")
    assert result is False


def test_check_if_downgrade_complex_upgrade():
    """Test upgrade with lower minor but higher major."""
    result = check_if_downgrade("9.5.3", "10.0.0")
    assert result is False


def test_check_if_downgrade_complex_downgrade():
    """Test downgrade with higher minor but lower major."""
    result = check_if_downgrade("10.0.0", "9.5.3")
    assert result is True


# ============================================================================
# Tests for get_existing_forward_servers
# ============================================================================


def test_get_existing_forward_servers_success(mock_module):
    """Test successful parsing of forward servers."""
    mock_module.check_mode = False
    splunk_output = """Active forwards:
    10.0.0.1:9997
    10.0.0.2:9997
Configured but inactive forwards:
    none
"""
    mock_module.run_command.return_value = (0, splunk_output, "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == ["10.0.0.1:9997", "10.0.0.2:9997"]


def test_get_existing_forward_servers_check_mode(mock_module):
    """Test that check mode returns empty list without running command."""
    mock_module.check_mode = True

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []
    mock_module.run_command.assert_not_called()


def test_get_existing_forward_servers_command_fails(mock_module):
    """Test that command failure returns empty list and warns."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (1, "", "error message")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []
    mock_module.warn.assert_called_once()
    assert "Failed to list forward-servers" in mock_module.warn.call_args[0][0]


def test_get_existing_forward_servers_no_servers(mock_module):
    """Test parsing when no forward servers are configured."""
    mock_module.check_mode = False
    splunk_output = """Active forwards:
    none
Configured but inactive forwards:
    none
"""
    mock_module.run_command.return_value = (0, splunk_output, "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []


def test_get_existing_forward_servers_mixed_active_inactive(mock_module):
    """Test parsing with both active and inactive servers."""
    mock_module.check_mode = False
    splunk_output = """Active forwards:
    10.0.0.1:9997
Configured but inactive forwards:
    10.0.0.2:9997
"""
    mock_module.run_command.return_value = (0, splunk_output, "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == ["10.0.0.1:9997", "10.0.0.2:9997"]


def test_get_existing_forward_servers_empty_output(mock_module):
    """Test parsing with empty output."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "", "")

    result = get_existing_forward_servers(
        mock_module,
        "/opt/splunkforwarder",
        "admin",
        "password",
    )

    assert result == []


# ============================================================================
# Tests for get_deployment_server
# ============================================================================


def test_get_deployment_server_success(mock_module):
    """Test successful extraction of the URI."""
    fake_content = "[target-broker:deploymentServer]\ntargetUri = 10.0.0.1:8089"

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result == "10.0.0.1:8089"


def test_get_deployment_server_no_file(mock_module):
    """Test when file does not exist."""
    with patch("os.path.exists", return_value=False):
        result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result is None


def test_get_deployment_server_missing_uri(mock_module):
    """Test when file exists but targetUri is missing."""
    fake_content = "[some-other-section]\nkey = value"

    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=fake_content)):
            result = get_deployment_server(mock_module, "/opt/splunkforwarder")

    assert result is None


# ============================================================================
# Tests for check_splunk_service
# ============================================================================


def test_check_splunk_service_start_success(mock_module):
    """Test successful detection of running service."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (0, "splunkd is running", "")
    mock_module.log = MagicMock()

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "start",
            max_retries=1,
        )

    assert result is True
    mock_module.fail_json.assert_not_called()


def test_check_splunk_service_stop_success(mock_module):
    """Test successful detection of stopped service."""
    mock_module.check_mode = False
    mock_module.run_command.return_value = (3, "splunkd is not running", "")
    mock_module.log = MagicMock()

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "stop",
            max_retries=1,
        )

    assert result is True
    mock_module.fail_json.assert_not_called()


def test_check_splunk_service_check_mode(mock_module):
    """Test that check mode returns True without running command."""
    mock_module.check_mode = True

    result = check_splunk_service(mock_module, "/opt/splunkforwarder", "start")

    assert result is True
    mock_module.run_command.assert_not_called()


def test_check_splunk_service_invalid_state(mock_module):
    """Test failure with invalid desired state."""
    mock_module.check_mode = False

    with pytest.raises(SystemExit):
        check_splunk_service(mock_module, "/opt/splunkforwarder", "invalid")

    mock_module.fail_json.assert_called_once()
    assert "Invalid desired_state" in mock_module.fail_json.call_args[1]["msg"]


def test_check_splunk_service_start_retry_success(mock_module):
    """Test that service check retries and eventually succeeds."""
    mock_module.check_mode = False
    mock_module.log = MagicMock()
    # First call returns not running, second call returns running
    mock_module.run_command.side_effect = [
        (3, "splunkd is not running", ""),
        (0, "splunkd is running", ""),
    ]

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "start",
            max_retries=2,
            retry_delay=1,
        )

    assert result is True
    assert mock_module.run_command.call_count == 2


def test_check_splunk_service_max_retries_exhausted(mock_module):
    """Test that max retries returns False."""
    mock_module.check_mode = False
    mock_module.log = MagicMock()
    # Always return not running
    mock_module.run_command.return_value = (3, "splunkd is not running", "")

    with patch("plugins.modules.splunk_universal_forwarder_linux.time.sleep"):
        result = check_splunk_service(
            mock_module,
            "/opt/splunkforwarder",
            "start",
            max_retries=2,
            retry_delay=1,
        )

    assert result is False
    assert mock_module.run_command.call_count == 2
