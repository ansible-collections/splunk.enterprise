# Splunk Enterprise Collection Release Notes

**Topics**

- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#bugfixes">Bugfixes</a>
    - <a href="#new-modules">New Modules</a>

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary"></a>
### Release Summary

Release summary for 1\.0\.0

<a id="minor-changes"></a>
### Minor Changes

* splunk\_universal\_forwarder\_linux \- new module to install and bootstrap Splunk Universal Forwarder on Linux\.
* splunk\_universal\_forwarder\_linux\_info \- new module to gather information about Splunk Universal Forwarder on Linux\.
* win\_splunk\_universal\_forwarder \- new module to install and bootstrap Splunk Universal Forwarder on Windows\.
* win\_splunk\_universal\_forwarder\_info \- new module to gather information about Splunk Universal Forwarder on Windows\.

<a id="bugfixes"></a>
### Bugfixes

* splunk\_universal\_forwarder\_linux \- handle exit code 8 from boot\-start command as success to enable service\.
* splunk\_universal\_forwarder\_linux \- removed version 9 only restriction to support newer versions\.
* splunk\_universal\_forwarder\_linux \- use systemctl for managing SplunkForwarder service instead of splunk binary commands\.

<a id="new-modules"></a>
### New Modules

* splunk\.enterprise\.splunk\_universal\_forwarder\_linux \- Manage Splunk Universal Forwarder installations on RHEL systems\.
* splunk\.enterprise\.splunk\_universal\_forwarder\_linux\_info \- Gather information about Splunk Universal Forwarder installations on RHEL systems\.
* splunk\.enterprise\.win\_splunk\_universal\_forwarder \- Install and bootstrap Splunk Universal Forwarder on Windows\.
* splunk\.enterprise\.win\_splunk\_universal\_forwarder\_info \- Gather information about Splunk Universal Forwarder on Windows\.
