#!/bin/sh
# Does the release that install.sh installs by default exist publicly?
#
# `main/install.sh` is what the README tells people to run, and it pins one version. If a
# commit that bumps that pin reaches main before the release is published, every new install
# fails with HTTP 404 until it is (it fails closed: nothing is replaced). The safe order is:
# tag the verified commit, let CI publish the release, then merge (docs/RELEASING.md).
#
#   tag build        skipped: the release job of this very run publishes it
#   push to main     FAIL when the release is missing: the installer window is open
#   anything else    warning only: "published: no" means do not merge yet
#
# Only HTTP 404 counts as "not published"; a network problem is reported, never a failure.
set -eu
repo=${GITHUB_REPOSITORY:-VAR7IANT/Rout}
here=$(dirname "$0")
version=$(sed -n 's/^VERSION=\${ROUT_VERSION:-\(v[0-9][0-9A-Za-z._-]*\)}$/\1/p' "$here/../install.sh")
[ -n "$version" ] || { echo "cannot read the default version from install.sh" >&2; exit 2; }
event=${GITHUB_EVENT_NAME:-}
ref=${GITHUB_REF:-}
case "$event:$ref" in
push:refs/tags/*) echo "tag build: $version is published by the release job of this run"; exit 0 ;;
esac
code=$(curl --proto '=https' --tlsv1.2 -sSL --connect-timeout 15 --max-time 60 -o /dev/null -w '%{http_code}' \
    "https://github.com/$repo/releases/download/$version/checksums.txt" 2>/dev/null) || code=000
case "$code" in
200)
    echo "install.sh installs $version: the release is published"
    ;;
404)
    msg="install.sh installs $version, but that release is not published. Publish it first (tag the verified commit, let CI release it), THEN merge: until then main's installer would answer HTTP 404. See docs/RELEASING.md."
    if [ "$event:$ref" = push:refs/heads/main ]; then
        echo "::error title=Installer window open::$msg"
        exit 1
    fi
    echo "::warning title=Release not published yet::$msg"
    ;;
*)
    echo "::warning title=Release check inconclusive::could not determine whether $version is published (HTTP $code)"
    ;;
esac
