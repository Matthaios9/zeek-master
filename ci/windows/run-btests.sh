#!/bin/bash


set -o pipefail

export MSYS=disable_pcon

BTEST="python ../../auxil/btest/btest"
JOBS=${ZEEK_CI_CPUS:-8}
RETRIES=${ZEEK_CI_BTEST_RETRIES:-3}

${BTEST} -z ${RETRIES} -j ${JOBS} -d -x btest-results.xml
result=$?



mkdir -p ${CIRCLE_WORKING_DIRECTORY}/btest-results/$1
cp btest-results.xml ${CIRCLE_WORKING_DIRECTORY}/btest-results/$1/results.xml

if [ ${result} -ne 0 ] && [ -f .btest.failed.dat ]; then
    echo "=== Initial btest run had failures, retrying after cleanup ==="



    failed_tests=""
    while IFS= read -r test_name; do
        test_name="${test_name%$'\r'}"
        [ -z "${test_name}" ] && continue

        test_path="${test_name//.//}"

        match=$(ls ${test_path}.* 2>/dev/null | head -1)
        if [ -n "${match}" ]; then
            failed_tests="${failed_tests} ${match}"
        else
            echo "Warning: could not resolve test '${test_name}' to a file"
        fi
    done <.btest.failed.dat

    if [ -z "${failed_tests}" ]; then
        echo "No failed tests could be resolved, skipping retry"
        exit ${result}
    fi


    taskkill //F //IM python.exe 2>/dev/null || true
    taskkill //F //IM zeek.exe 2>/dev/null || true


    rm -rf .tmp


    echo "Retrying:${failed_tests}"
    ${BTEST} -z ${RETRIES} -j ${JOBS} -d -x btest-results.xml ${failed_tests}
    result=$?

    if [ ${result} -ne 0 ] && [ -f .btest.failed.dat ]; then
        echo ""
        echo "=== Tests still failing after retry ==="
        cat .btest.failed.dat
        echo "======================================="
    fi
fi


if [ -d .tmp ]; then
    rm -rf .tmp/script-coverage
    tar -czf tmp.tar.gz .tmp 2>/dev/null || true
fi

exit ${result}
