#! /usr/bin/env bash

ZEEK_BENCHMARK_ENDPOINT="/zeek"


set -e


if [[ ${ZEEK_CI_INTERNAL_BUILD:-0} != 1 || "${CIRCLE_PROJECT_REPONAME}" != "zeek" ]]; then
    echo "Benchmarking skipped for jobs from forks"
    exit 0
fi


BUILD_URL="https://output.circle-artifacts.com/output/job/${CIRCLE_WORKFLOW_JOB_ID}/artifacts/0/install.tgz"



BUILD_HASH=$(sha256sum ${ZEEK_CI_WORKING_DIR}/install.tgz | awk '{print $1}')



TIMESTAMP=$(date -u +'%s')
HMAC_DIGEST=$(echo "${ZEEK_BENCHMARK_ENDPOINT}-${TIMESTAMP}-${BUILD_HASH}" | openssl dgst -sha256 -hmac ${ZEEK_BENCHMARK_HMAC_KEY} | awk '{print $2}')

TARGET="https://${ZEEK_BENCHMARK_HOST}:${ZEEK_BENCHMARK_PORT}${ZEEK_BENCHMARK_ENDPOINT}"



set +e







curl -sS -G --stderr - --fail --insecure -X POST \
    -o "${ZEEK_CI_WORKING_DIR}/benchmark-${TIMESTAMP}.log" \
    -H "Zeek-HMAC: ${HMAC_DIGEST}" \
    -H "Zeek-HMAC-Timestamp: ${TIMESTAMP}" \
    --data-urlencode "branch=${CIRCLE_BRANCH}" \
    --data-urlencode "build=${BUILD_URL}" \
    --data-urlencode "build_hash=${BUILD_HASH}" \
    --data-urlencode "commit=${CIRCLE_SHA1}" \
    --data-urlencode "cirrus_repo_owner=${CIRCLE_PROJECT_USERNAME}" \
    --data-urlencode "cirrus_repo_name=${CIRCLE_PROJECT_REPONAME}" \
    --data-urlencode "cirrus_task_id=${CIRCLE_WORKFLOW_JOB_ID}" \
    --data-urlencode "cirrus_task_name=$(echo ${CIRCLE_JOB} | sed 's/ubuntu-24\./ubuntu24_/' | tr '-' '_')" \
    --data-urlencode "cirrus_build_id=${CIRCLE_BUILD_NUM}" \
    --data-urlencode "cirrus_pr=$(echo ${CIRCLE_PULL_REQUEST} | awk -F/ '{print $NF}')" \
    --data-urlencode "repo_version=$(cat ./VERSION)" \
    "${TARGET}"

STATUS=$?



if [ $STATUS -ne 0 ]; then
    cat ${ZEEK_CI_WORKING_DIR}/benchmark-${TIMESTAMP}.log | sed "s/${ZEEK_BENCHMARK_HOST}/<secret>/g" | sed "s/:${ZEEK_BENCHMARK_PORT}/:<secret>/g"
else
    cat ${ZEEK_CI_WORKING_DIR}/benchmark-${TIMESTAMP}.log
fi

exit $STATUS
