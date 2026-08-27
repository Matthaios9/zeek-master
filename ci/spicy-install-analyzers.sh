#! /usr/bin/env bash




test -d ${ZEEK_CI_WORKING_DIR}/install


PREFIX=${ZEEK_CI_WORKING_DIR}/install
echo $PREFIX

export PATH=$PREFIX/bin:$PATH

zkg --version

ANALYZERS="
https://github.com/zeek/spicy-dhcp
https://github.com/zeek/spicy-http
"

for analyzer in $ANALYZERS; do
    echo Y | zkg -vvvvv install "${analyzer}"
done



tar -czf ${ZEEK_CI_WORKING_DIR}/build.tgz ${ZEEK_CI_WORKING_DIR}/install
