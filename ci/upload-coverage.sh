#! /usr/bin/env bash





if [ ${ZEEK_CI_INTERNAL_BUILD:-0} -ne 1 ]; then
    echo "Coverage upload skipped for jobs from forks"
    exit 0
fi

cd testing/coverage
make coverage
make coveralls
