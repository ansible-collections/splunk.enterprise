==========================================
Splunk Enterprise Collection Release Notes
==========================================

.. contents:: Topics

v1.0.0
======

Release Summary
---------------

Release summary for 1.0.0

Minor Changes
-------------

- splunk_universal_forwarder_linux - new module to install and bootstrap Splunk Universal Forwarder on Linux.
- splunk_universal_forwarder_linux_info - new module to gather information about Splunk Universal Forwarder on Linux.
- win_splunk_universal_forwarder - new module to install and bootstrap Splunk Universal Forwarder on Windows.
- win_splunk_universal_forwarder_info - new module to gather information about Splunk Universal Forwarder on Windows.

Bugfixes
--------

- splunk_universal_forwarder_linux - handle exit code 8 from boot-start command as success to enable service.
- splunk_universal_forwarder_linux - removed version 9 only restriction to support newer versions.
- splunk_universal_forwarder_linux - use systemctl for managing SplunkForwarder service instead of splunk binary commands.

New Modules
-----------

- splunk.enterprise.splunk_universal_forwarder_linux - Manage Splunk Universal Forwarder installations on RHEL systems.
- splunk.enterprise.splunk_universal_forwarder_linux_info - Gather information about Splunk Universal Forwarder installations on RHEL systems.
- splunk.enterprise.win_splunk_universal_forwarder - Install and bootstrap Splunk Universal Forwarder on Windows.
- splunk.enterprise.win_splunk_universal_forwarder_info - Gather information about Splunk Universal Forwarder on Windows.
