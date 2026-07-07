#!/usr/bin/env bash

set -o pipefail -eux

declare -a args
IFS='/:' read -ra args <<< "$1"

version="${args[1]}"
connection="${args[2]}"
connection_setting="${args[3]}"

if [ "${#args[0]}" -gt 4 ]; then
    target="shippable/windows/group${args[4]}/"
else
    target="shippable/windows/"
fi

stage="${S:-prod}"
provider="${P:-default}"

if [ "${ANSIBLE_VERSION:-}" == "2.16" ]; then
    ansible-test windows-integration --color -v --retry-on-error "${target}" ${COVERAGE:+"$COVERAGE"} ${CHANGED:+"$CHANGED"} ${UNSTABLE:+"$UNSTABLE"} \
        --controller "docker:default" \
        --target "remote:windows/${version},provider=${provider}" \
        --remote-terminate always --remote-stage "${stage}"
else
    ansible-test windows-integration --color -v --retry-on-error "${target}" ${COVERAGE:+"$COVERAGE"} ${CHANGED:+"$CHANGED"} ${UNSTABLE:+"$UNSTABLE"} \
        --controller "docker:default" \
        --target "remote:windows/${version},connection=${connection}+${connection_setting},provider=${provider}" \
        --remote-terminate always --remote-stage "${stage}"
fi
