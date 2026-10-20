#!/bin/sh
# Run only against a disposable container's own network namespace.
set -eu
[ "$#" -ge 2 ] || { echo 'Usage: test-nft-container.sh STATIC_TEST STATIC_MANAGER [ENGINE_DIR]' >&2; exit 1; }
test_binary=$(realpath "$1")
manager_binary=$(realpath "$2")
engine_dir=${3:-}
set -- --mount "type=bind,src=$test_binary,dst=/w/rout.test,readonly" \
    --mount "type=bind,src=$manager_binary,dst=/w/rout,readonly"
if [ -n "$engine_dir" ]; then
    engine_dir=$(realpath "$engine_dir")
    set -- "$@" --mount "type=bind,src=$engine_dir,dst=/w/engines,readonly" -e ROUT_TEST_ENGINES=/w/engines
fi
# Docker supplies its configured proxy variables. No host network or global flush.
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW "$@" debian:12 sh -ec '
    apt-get update -qq
    apt-get install -y -qq nftables iproute2 >/dev/null
    nft --version
    if ! nft list tables 2>/tmp/nft-capability-error; then
        cat /tmp/nft-capability-error >&2
        if grep -Eq "Operation not permitted|Permission denied|Protocol not supported|Operation not supported" /tmp/nft-capability-error; then
            echo "SKIP: nftables kernel support/CAP_NET_ADMIN unavailable" >&2
            exit 2
        fi
        exit 1
    fi
    ip link set lo up
    ROUT_TEST_NFT=1 ROUT_TEST_NFT_VERSION=1.0.6 ROUT_TEST_MANAGER=/w/rout \
        /w/rout.test -test.run "^TestKernel" -test.v
'
