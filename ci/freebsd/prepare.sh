#!/bin/sh

echo "Preparing FreeBSD environment"
sysctl hw.model hw.machine hw.ncpu
set -e
set -x

env ASSUME_ALWAYS_YES=YES pkg bootstrap

pkg install -y bash cppzmq git cmake-core swig bison python3 base64 flex ccache jq dnsmasq krb5
pkg upgrade -y curl
pyver=$(python3 -c 'import sys; print(f"py{sys.version_info[0]}{sys.version_info[1]}")')
pkg install -y $pyver-sqlite3
python3 -m ensurepip --upgrade

python3 -m pip install websockets junit2html


echo "proc /proc procfs rw,noauto 0 0" >>/etc/fstab
mount /proc


ln -s /usr/local/sbin/dnsmasq /usr/local/bin/dnsmasq
