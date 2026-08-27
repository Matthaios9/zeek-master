#!/bin/bash










set -euo pipefail

REMOTE=${REMOTE:-origin}
MAIN_BRANCH=${MAIN_BRANCH:-refs/remotes/${REMOTE}/master}

function usage() {
    echo "Usage $0 <lts|feature>" >&2
    exit 1
}

if [ $
    usage
fi

if [ "${1}" = "lts" ]; then
    PATTERN=".* refs/remotes/${REMOTE}/release/[0-9]+\.0\$"
elif [ "${1}" = "feature" ]; then
    PATTERN=".* refs/remotes/${REMOTE}/release/[0-9]+\.[0-9]+\$"
else
    usage
fi




for ref in $(git show-ref | grep -E "${PATTERN}" | awk '{ print $2 }' | sort -rn); do
    version=$(echo $ref | sed -E 's,^.*/(.+)$,\1,g')
    tag_ref="refs/tags/v${version}.0"


    tag_obj=$(git rev-list -n 1 "${tag_ref}" 2>/dev/null || true)



    if [ -z "${tag_obj}" ]; then
        continue
    fi



    merge_base=$(git merge-base $MAIN_BRANCH $ref)
    if git rev-list ${merge_base}..${ref} | grep -q "^${tag_obj}$"; then
        echo "${version}"
        exit 0
    fi
done

exit 1
