.. _splunk.enterprise.splunk_universal_forwarder_linux_module:


**************************************************
splunk.enterprise.splunk_universal_forwarder_linux
**************************************************

**Manage Splunk Universal Forwarder installations on RHEL systems**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- This module manages Splunk Universal Forwarder installations on RHEL 8, 9, and 10 systems with RPM package.
- Support Universal Forwarder version 9 only. Version 10.0.0 and above is not supported.
- Downloads the Splunk Universal Forwarder RPM and verifies its integrity using SHA512 checksums.
- Supports idempotent installation and removal of the forwarder.
- Automatically configures user credentials and starts the forwarder on first installation.
- If the forwarder is already installed, only upgrades are allowed.
- To downgrade the forwarder, you can use 2 tasks - absent then present.
- Password is set on first installation only, On subsequent tasks the user/password has to be provided.




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
                    <b>cpu</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>64-bit</b>&nbsp;&larr;</div></li>
                                    <li>ARM</li>
                        </ul>
                </td>
                <td>
                        <div>CPU architecture for the Splunk Universal Forwarder package.</div>
                        <div>V(64-bit) for x86_64 architecture.</div>
                        <div>V(ARM) for aarch64 architecture.</div>
                </td>
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
                        <div>The Splunk Deployment Server to register with.</div>
                        <div>Must be in V(&lt;host&gt;:&lt;port&gt;) format (e.g., V(deployment-server.example.com:8089)).</div>
                        <div>The default Splunk deployment server port is V(8089).</div>
                        <div>When specified, configures the forwarder to poll this deployment server for apps and configurations.</div>
                        <div>When set to an empty string, removes the deployment server configuration and restarts the forwarder service.</div>
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
                        <div>List of Splunk Enterprise servers to forward data to.</div>
                        <div>Each entry must be in V(&lt;host&gt;:&lt;port&gt;) format (e.g., V(splunk-indexer.example.com:9997)).</div>
                        <div>The default Splunk receiving port is typically V(9997).</div>
                        <div>When specified, configures the forwarder to send data to these servers, Sets the forward-servers exactly to this list.</div>
                        <div>When list is empty, The current configured forward-servers will be removed, and the configuration will be empty.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>password</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Password for the Splunk admin account.</div>
                        <div>Required when O(state=present).</div>
                        <div>Will be set to this value on scratch installation.</div>
                        <div>Required to retrieve information on subsequent tasks.</div>
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
                        <div>Release id corresponding to the Splunk Universal Forwarder version (e.g., V(2a9293b80994)).</div>
                        <div>The release id can be found on the Splunk download page for each version.</div>
                        <div>Combined with O(version) to form the RPM filename (e.g., V(9.4.7-2a9293b80994)).</div>
                        <div>Required when O(state=present).</div>
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
                        <div>V(present) ensures the forwarder is installed and configured.</div>
                        <div>V(absent) ensures the forwarder is removed from the system and all configuration is removed.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>username</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Username for the Splunk admin account.</div>
                        <div>Required when O(state=present).</div>
                        <div>User Will be craeted on scratch installation.</div>
                        <div>Required to retrieve information on subsequent tasks.</div>
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
                        <div>Version of Splunk Universal Forwarder to install (e.g., V(9.4.7)).</div>
                        <div>Only major version 9 is supported. Version 10.0.0 and above is not supported.</div>
                        <div>Required when O(state=present).</div>
                </td>
            </tr>
    </table>
    <br/>


Notes
-----

.. note::
   - This module only works on RHEL 8, 9, and 10 systems.
   - Only Splunk Universal Forwarder major version 9 is supported. Version 10.0.0 and above is not supported.
   - The RPM package will be downloaded to V(/opt) from the official Splunk download site.
   - Splunk Universal Forwarder will be installed to V(/opt/splunkforwarder).
   - Requires root privileges to install/remove packages and start services.
   - The RPM filename is constructed as V(splunkforwarder-{version}-{release_id}.{cpu_arch}.rpm).
   - When upgrading from a previous version, $SPLUNK_HOME/etc & $SPLUNK_HOME/var directories will be preserved to save previous data.



Examples
--------

.. code-block:: yaml

    - name: Install Splunk Universal Forwarder (x86_64)
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: present
        version: "9.4.7"
        release_id: "2a9293b80994"
        username: admin
        password: "changeme123"

    - name: Install Splunk Universal Forwarder on ARM architecture, with no forward-servers configured
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: present
        version: "9.4.7"
        release_id: "2a9293b80994"
        cpu: ARM
        username: admin
        password: "changeme123"
        forward_servers: []

    - name: Install Splunk Universal Forwarder with forward-servers configuration
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: present
        version: "9.4.7"
        release_id: "2a9293b80994"
        username: admin
        password: "changeme123"
        forward_servers:
          - "splunk-indexer1.example.com:9997"
          - "192.168.1.100:9997"

    - name: Install Splunk Universal Forwarder with deployment server
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: present
        version: "9.4.7"
        release_id: "2a9293b80994"
        username: admin
        password: "changeme123"
        deployment_server: "deployment-server.example.com:8089"

    - name: Remove deployment server configuration
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: present
        version: "9.4.7"
        release_id: "2a9293b80994"
        username: admin
        password: "changeme123"
        deployment_server: ""

    - name: Remove Splunk Universal Forwarder
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: absent

    - name: Install Splunk Universal Forwarder (check mode)
      splunk.enterprise.splunk_universal_forwarder_linux:
        state: present
        version: "9.4.7"
        release_id: "2a9293b80994"
        username: admin
        password: "changeme123"
      check_mode: true



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>changed</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">boolean</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Whether any changes were made.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">True</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>cpu_arch</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state is present</td>
                <td>
                            <div>CPU architecture used for the installation.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">x86_64</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>msg</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Human-readable message describing the action taken.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">Splunk Universal Forwarder 10.0.1 installed successfully</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>release_id</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state is present</td>
                <td>
                            <div>Release id corresponding to the version.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">c486717c322b</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>rpm_path</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state is present</td>
                <td>
                            <div>Path where the RPM file was downloaded.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">/opt/splunkforwarder-10.0.1-c486717c322b.x86_64.rpm</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>splunk_home</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>Installation directory of Splunk Universal Forwarder.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">/opt/splunkforwarder</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>version</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">string</span>
                    </div>
                </td>
                <td>when state is present</td>
                <td>
                            <div>Version of Splunk Universal Forwarder that was installed.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">10.0.1</div>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Shahar Golshani (@shahargolshani)
