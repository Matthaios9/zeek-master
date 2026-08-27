#!/bin/bash














set -eux

REGISTRY_PREFIX=${REGISTRY_PREFIX:-}
ZEEK_IMAGE_REPO=${ZEEK_IMAGE_REPO:-zeek}

ADDITIONAL_MANIFEST_TAGS=${ADDITIONAL_MANIFEST_TAGS:-}


if [ -n "${REGISTRY_PREFIX}" ]; then
    if [[ ! "${REGISTRY_PREFIX}" =~ .+/$ ]]; then
        echo "Missing slash in: ${REGISTRY_PREFIX}"
        exit 1
    fi
fi


function do_docker {
    if ! docker "$@"; then
        echo "docker invocation failed. retrying in 5 seconds." >&2
        sleep 5
        docker "$@"
    fi
}

function create_and_push_manifest {

    do_docker buildx imagetools create \
        --debug \
        --tag ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${1} \
        ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-arm64 \
        ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-amd64
}

do_docker tag zeek/zeek-multiarch:arm64 ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-arm64
do_docker tag zeek/zeek-multiarch:amd64 ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-amd64
do_docker push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-arm64
do_docker push ${REGISTRY_PREFIX}${ZEEK_IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}-amd64

create_and_push_manifest ${IMAGE_TAG}

if [ -n "${ADDITIONAL_MANIFEST_TAGS}" ]; then

    for tag in ${ADDITIONAL_MANIFEST_TAGS}; do
        create_and_push_manifest ${tag}
    done
fi
