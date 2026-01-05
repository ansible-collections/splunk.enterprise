.. _splunk.enterprise.win_splunk_universal_forwarder_module:


************************************************
splunk.enterprise.win_splunk_universal_forwarder
************************************************

**Install and bootstrap Splunk Universal Forwarder on Windows**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Downloads the Splunk Universal Forwarder MSI for a requested version and installs it silently.
- Seeds initial credentials via ``user-seed.conf`` and configures deployment/forward servers using ``splunk.exe`` authenticated via environment variables.
- Supports upgrades to newer versions (downgrade is not supported).
- Configures forward servers and deployment server.




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>deployment_server</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Deployment server in <code>ip:port</code> format or hostname:port format.</div>
                        <div>To clear the configured deployment server, use the special value <code>&quot;NONE&quot;</code>.</div>
                        <div>When clearing, the module will remove <code>deploymentclient.conf</code> and restart Splunk.</div>
                        <div>If omitted entirely, the deployment server configuration is not modified.</div>
                        <div>Example: &#x27;10.1.1.1:8089&#x27; or &#x27;domain.test.com:8089&#x27;</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>forward_servers</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Desired list of forward servers in <code>ip:port</code> format or hostname:port format.</div>
                        <div>To clear all configured forward servers, use an explicit empty list <code>forward_servers{{&#x27;:&#x27;}} []</code>.</div>
                        <div>If omitted entirely, forward servers are not modified.</div>
                        <div>Example: [&#x27;10.1.1.1:9997&#x27;, &#x27;domain.test.com:9997&#x27;]</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>install_dir</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">path</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"C:\\Program Files\\SplunkUniversalForwarder"</div>
                </td>
                <td>
                        <div>Installation directory for Splunk Universal Forwarder.</div>
                        <div>Also used for version detection and running <code>splunk.exe</code> commands.</div>
                        <div>IMPORTANT: This parameter cannot be changed after installation.</div>
                        <div>The install directory is set during initial installation and cannot be moved via MSI upgrade.</div>
                        <div>If you installed Splunk to a non-default directory, you MUST provide the same <code>install_dir</code> value.</div>
                        <div>This is required for all subsequent runs (upgrades, configuration changes, etc.).</div>
                        <div>The module needs to know the correct installation directory to detect the installed version and execute commands.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>purge</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>no</b>&nbsp;&larr;</div></li>
                                    <li>yes</li>
                        </ul>
                </td>
                <td>
                        <div>When <code>state=absent</code>, purge Splunk UF files/config directories and temp directory after uninstall.</div>
                        <div>This will remove both the installation directory and the temp directory (default <code>C:\splunktemp</code>) with all downloaded files.</div>
                        <div>Be careful with this option, as it will remove all files and the temp folder even if it was present before the module run.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>release_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Release identifier used in the download filename (for example <code>e2d18b4767e9</code> for <code>10.0.2</code>).</div>
                        <div>This is the suffix between the version and platform in the MSI filename.</div>
                        <div>Example: <code>splunkforwarder-&lt;version&gt;-&lt;hash&gt;-windows-x64.msi</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>service_account_type</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>local_system</b>&nbsp;&larr;</div></li>
                                    <li>virtual_service_account</li>
                                    <li>domain_user</li>
                        </ul>
                </td>
                <td>
                        <div>Type of service account to use for running the Splunk Universal Forwarder service.</div>
                        <div><code>local_system</code> uses the Local System account (USE_LOCAL_SYSTEM=1).</div>
                        <div><code>virtual_service_account</code> uses a virtual service account (default MSI behavior without USE_LOCAL_SYSTEM).</div>
                        <div>This option is recommended for production environments.</div>
                        <div>When using <code>virtual_service_account</code>, there might be inconsistencies while installing.</div>
                        <div>Failures might occur; recommendation is to run with retry logic.</div>
                        <div><code>domain_user</code> uses a specific domain or local user account (requires <code>service_logon_username</code> and <code>service_logon_password</code>).</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>service_logon_password</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Password for the service account.</div>
                        <div>Required when <code>service_account_type=domain_user</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>service_logon_username</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Username for the service account (in format <code>domain\username</code> or <code>.\username</code> for local accounts).</div>
                        <div>Required when <code>service_account_type=domain_user</code>.</div>
                        <div>This parameter specifies the user account that the SplunkForwarder service will run as.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>splunk_password</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Initial Splunk admin password to write to <code>user-seed.conf</code> and to authenticate <code>splunk.exe</code> commands via environment variables.</div>
                        <div>Required when <code>state=present</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>splunk_username</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Initial Splunk admin username to write to <code>user-seed.conf</code> and to authenticate <code>splunk.exe</code> commands via environment variables.</div>
                        <div>Required when <code>state=present</code>.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>state</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>present</b>&nbsp;&larr;</div></li>
                                    <li>absent</li>
                        </ul>
                </td>
                <td>
                        <div>Whether the Splunk Universal Forwarder should be installed or removed.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>temp_dir</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"C:\\splunktemp"</div>
                </td>
                <td>
                        <div>Directory on the Windows host to store the downloaded MSI and installation logs.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>version</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Splunk Universal Forwarder version to install or upgrade to (for example <code>10.0.2</code>).</div>
                        <div>If a lower version than currently installed is specified, the module will fail with a downgrade error.</div>
                        <div>If the same version is already installed, only configuration changes will be applied.</div>
                        <div>If a higher version is specified, an upgrade will be performed.</div>
                </td>
            </tr>
    </table>
    <br/>


Notes
-----

.. note::
   - When using ``service_account_type=domain_user``, ensure the specified user has appropriate permissions to run services and access Splunk directories.
   - Upgrades are performed using the same msiexec command as installations. Downgrades are not supported.
   - When the same version is already installed, the module will only apply configuration changes (forward servers, deployment server, etc.).
   - If the MSI installer returns exit code 3010, a warning will be displayed indicating that a system reboot is required.



Examples
--------

.. code-block:: yaml

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



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="2">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>changed</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Whether the module made any changes.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>checksum_path</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state=present</td>
                <td>
                            <div>Full path where the SHA512 checksum file was stored on the Windows host.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>checksum_url</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state=present</td>
                <td>
                            <div>URL used to download the SHA512 checksum file.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>deploymentclient_conf_removed</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>when deployment_server is set to NONE</td>
                <td>
                            <div>Whether deploymentclient.conf was removed when clearing deployment server.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>download_url</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state=present</td>
                <td>
                            <div>URL used to download the MSI.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>installed</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Whether the SplunkForwarder service is present after execution.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>installed_version</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state=present</td>
                <td>
                            <div>Installed version detected via <code>splunk.exe version</code> (best-effort).</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>msi_path</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state=present</td>
                <td>
                            <div>Full path where the MSI was stored on the Windows host.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>purged_install_dir</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>when state=absent and purge=true</td>
                <td>
                            <div>Whether the installation directory was successfully purged during uninstall.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>purged_temp_dir</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>when state=absent and purge=true</td>
                <td>
                            <div>Whether the temp directory was successfully purged during uninstall.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>reboot_required</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Whether the MSI returned 3010 indicating a reboot is required.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>service</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>SplunkForwarder service details.</div>
                    <br/>
                </td>
            </tr>
                                <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>name</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td></td>
                <td>
                            <div>Service name.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>start_type</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td></td>
                <td>
                            <div>Service startup type (Automatic, Manual, etc.).</div>
                    <br/>
                </td>
            </tr>
            <tr>
                    <td class="elbow-placeholder">&nbsp;</td>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>status</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td></td>
                <td>
                            <div>Service status (Running, Stopped, etc.).</div>
                    <br/>
                </td>
            </tr>

            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>splunk_restarted_for_deploy_clear</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>when deployment_server is set to NONE</td>
                <td>
                            <div>Whether Splunk was restarted after clearing deployment server.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>splunk_stop_attempted</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>when state=absent</td>
                <td>
                            <div>Whether the module attempted to stop Splunk before uninstalling.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>splunk_stop_error</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state=absent and splunk_stopped is false</td>
                <td>
                            <div>Error message if stopping Splunk failed.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>splunk_stopped</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>when state=absent and splunk_stop_attempted is true</td>
                <td>
                            <div>Whether the Splunk service was successfully stopped before uninstall.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="2">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>version_comparison</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>when state=present and version is already installed</td>
                <td>
                            <div>Result of version comparison (-1 if installed &lt; requested, 0 if equal, 1 if installed &gt; requested).</div>
                    <br/>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Ron Gershburg (@rgershbu)
