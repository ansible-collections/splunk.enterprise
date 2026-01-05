# Splunk Enterprise Ansible Collection

<!-- Add CI and code coverage badges here. Samples included below. -->

[![Collection Tests - Sanity | SonarCloud | Ansible-Lint | Unit](https://github.com/ansible-collections/splunk.enterprise/actions/workflows/tests.yml/badge.svg?event=schedule)](https://github.com/ansible-collections/splunk.enterprise/actions/workflows/tests.yml)
[![Integration Tests](https://github.com/ansible-collections/splunk.enterprise/actions/workflows/integration.yml/badge.svg)](https://github.com/ansible-collections/splunk.enterprise/actions/workflows/integration.yml)

<!-- Describe the collection and why a user would want to use it. What does the collection do? -->

The Ansible Enterprise collection includes variety of content to help automate lifecycle management of Splunk Enterprise related functionality.

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/projects/ansible/devel/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior, please refer to the [policy violations](https://docs.ansible.com/projects/ansible/devel/community/code_of_conduct.html#policy-violations) section of the Code for information on how to raise a complaint.

## Communication

<!--
If your collection is not present on the Ansible forum yet, please check out the existing [tags](https://forum.ansible.com/tags) and [groups](https://forum.ansible.com/g) - use what suits your collection. If there is no appropriate tag and group yet, please [request one](https://forum.ansible.com/t/requesting-a-forum-group/503/17).
-->

- Join the Ansible forum:
  - [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions
  - [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  - [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events. The [Bullhorn newsletter](https://docs.ansible.com/projects/ansible/devel/community/communication.html#the-bullhorn), which is used to announce releases and important changes, can also be found here.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/projects/ansible/devel/community/communication.html).

## Contributing to this collection

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [Splunk Enterprise collection repository](https://github.com/ansible-collections/splunk.enterprise). See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

The content of this collection is made by people like you, a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors and all types of contributions are very welcome.

Don't know how to start? Refer to the [Ansible community guide](https://docs.ansible.com/projects/ansible/devel/community/index.html)!

Want to submit code changes? Take a look at the [Quick-start development guide](https://docs.ansible.com/projects/ansible/devel/community/create_pr_quick_start.html).

We also use the following guidelines:

- [Collection review checklist](https://docs.ansible.com/projects/ansible/devel/community/collection_contributors/collection_reviewing.html)
- [Ansible development guide](https://docs.ansible.com/projects/ansible/devel/dev_guide/index.html)
- [Ansible collection development guide](https://docs.ansible.com/projects/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

## Collection maintenance

The current maintainers are listed in the [MAINTAINERS](MAINTAINERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain/become a maintainer of this collection, refer to the [Maintainer guidelines](https://docs.ansible.com/projects/ansible/devel/community/maintainers.html).

It is necessary for maintainers of this collection to be subscribed to:

- The collection itself (the `Watch` button -> `All Activity` in the upper right corner of the repository's homepage).
- The [news-for-maintainers repository](https://forum.ansible.com/tags/c/project/7/news-for-maintainers).

They also should be subscribed to Ansible's [The Bullhorn newsletter](https://docs.ansible.com/projects/ansible/devel/community/communication.html#the-bullhorn).

## Governance

The process of decision making in this collection is based on discussing and finding consensus among participants.

Every voice is important. If you have something on your mind, create an issue or dedicated discussion and let's discuss it!

## Tested with Ansible

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against the following Ansible versions: **>=2.17.0**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

## Included content

<!--start collection content-->
### Modules
Name | Description
--- | ---
[splunk.enterprise.win_splunk_universal_forwarder](https://github.com/ansible-collections/splunk.enterprise/blob/main/docs/splunk.enterprise.win_splunk_universal_forwarder_module.rst)|Install and bootstrap Splunk Universal Forwarder on Windows
[splunk.enterprise.win_splunk_universal_forwarder_info](https://github.com/ansible-collections/splunk.enterprise/blob/main/docs/splunk.enterprise.win_splunk_universal_forwarder_info_module.rst)|Gather information about Splunk Universal Forwarder on Windows

<!--end collection content-->

## Using this collection

### Installing the Collection from Ansible Galaxy

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install splunk.enterprise
```

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: splunk.enterprise
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the `ansible` package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install splunk.enterprise --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version `0.1.0`:

```bash
ansible-galaxy collection install splunk.enterprise:==0.1.0
```

See [using Ansible collections](https://docs.ansible.com/projects/ansible/devel/user_guide/collections_using.html) for more details.

## Release notes

See the [changelog](https://github.com/ansible-collections/splunk.enterprise/tree/main/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

<!-- List out where the user can find additional information, such as working group meeting times, slack/IRC channels, or documentation for the product this collection automates. At a minimum, link to: -->

- [Ansible user guide](https://docs.ansible.com/projects/ansible/devel/user_guide/index.html)
- [Ansible developer guide](https://docs.ansible.com/projects/ansible/devel/dev_guide/index.html)
- [Ansible collections requirements](https://docs.ansible.com/projects/ansible/devel/community/collection_contributors/collection_requirements.html)
- [Ansible community Code of Conduct](https://docs.ansible.com/projects/ansible/devel/community/code_of_conduct.html)
- [The Bullhorn (the Ansible contributor newsletter)](https://docs.ansible.com/projects/ansible/devel/community/communication.html#the-bullhorn)
- [Important announcements for maintainers](https://github.com/ansible-collections/news-for-maintainers)

## Licensing

<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
