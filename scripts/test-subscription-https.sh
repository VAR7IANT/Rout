#!/bin/sh
# A new Debian container: no production DNS, certificates, init units or firewall.
set -eu
[ "$#" = 1 ] || { echo 'Usage: test-subscription-https.sh STATIC_GO_TEST_BINARY' >&2; exit 1; }
test_binary=$(realpath "$1")
docker run --rm \
    --mount "type=bind,src=$test_binary,dst=/rout.test,readonly" \
    -e ROUT_TEST_CADDY=1 -e ROUT_TEST_CADDY_INSTALL=1 \
    debian:12 sh -ec '
        test ! -x /usr/bin/caddy
        exec /rout.test -test.run "^TestIntegrationSubscription(CaddyFreshDeployment|ExistingCaddyZeroLoss)$" -test.v
    '
