#!/bin/bash








set -eu

dir="$(cd "$(dirname "$0")" && pwd)"

if [ $
    echo "Usage: $0 <tag>" >&2
    exit 1
fi

TAG="${1}"




lts_ver=$(${dir}/find-current-version.sh lts)
lts_pat="^v$(echo $lts_ver | sed 's,\.,\\.,g')\.[0-9]+\$"
feature_ver=$(${dir}/find-current-version.sh feature)
feature_pat="^v$(echo $feature_ver | sed 's,\.,\\.,g')\.[0-9]+\$"




ADDL_MANIFEST_TAGS=()
if echo "${TAG}" | grep -q -E "${lts_pat}"; then
    ADDL_MANIFEST_TAGS+=(lts)
    ADDL_MANIFEST_TAGS+=(${lts_ver})
fi

if echo "${TAG}" | grep -q -E "${feature_pat}"; then
    ADDL_MANIFEST_TAGS+=(latest)
    if [ "${feature_ver}" != "${lts_ver}" ]; then
        ADDL_MANIFEST_TAGS+=(${feature_ver})
    fi
fi



echo "ADDITIONAL_MANIFEST_TAGS=\"${ADDL_MANIFEST_TAGS[*]}\""
