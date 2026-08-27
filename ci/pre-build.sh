


set -ex

if [ -n "$ZEEK_CI_PREBUILD_COMMAND" ]; then
    bash -c "$ZEEK_CI_PREBUILD_COMMAND"
fi
