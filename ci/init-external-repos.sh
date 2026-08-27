#! /usr/bin/env bash

function banner {
    local msg="${1}"
    printf "+--------------------------------------------------------------+\n"
    printf "| %-60s |\n" "$(date)"
    printf "| %-60s |\n" "${msg}"
    printf "+--------------------------------------------------------------+\n"
}

set -e

cd testing/external
[[ ! -d zeek-testing ]] && make init
cd zeek-testing

if [[ -n "${ZEEK_CI}" ]]; then
    if [[ -d ../zeek-testing-traces ]]; then
        banner "Use existing/cached zeek-testing traces"
    else
        banner "Create cache directory for zeek-testing traces"
        mkdir ../zeek-testing-traces
    fi

    rm -rf Traces
    ln -s ../zeek-testing-traces Traces
fi

make update-traces
cd ..






if [[ -n "${ZEEK_CI}" && ${ZEEK_CI_INTERNAL_BUILD} == 1 && ! -d zeek-testing-private ]]; then
    banner "Trying to clone zeek-testing-private git repo"
    GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no" git clone git@github.com:zeek/zeek-testing-private
fi

set -e

if [[ -d zeek-testing-private ]]; then

    banner "Update zeek-testing-private traces"
    cd zeek-testing-private
    git checkout -q $(cat ../commit-hash.zeek-testing-private)
    make update-traces
fi
