#!/bin/sh
# Regression test of the UNMODIFIED install.sh against local release artifacts.
#
# install.sh has no knob for another download source (that would be an unverified-source
# switch). The test puts a fake `curl` first on PATH that serves
#   https://github.com/VAR7IANT/Rout/releases/download/TAG/FILE
# from a local directory, logs every URL, and refuses any other URL. Run as root:
#   sh scripts/release.sh && sudo sh scripts/test-install.sh dist
#
# This proves the installer's logic (names, SHA256, version check, atomic replacement, fail
# closed on a missing release). It does not prove that GitHub serves the files: the CI step
# "Installer against the published release" and the real tag run do.
set -eu
[ "$#" = 1 ] || { echo 'Usage: test-install.sh DIST_DIR' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'install.sh needs root; run with sudo' >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
dist=$(cd "$1" && pwd)
repo_root=$(dirname "$here")
tag=$(cat "$dist/version.txt")
default=$(sed -n 's/^VERSION=\${ROUT_VERSION:-\(v[0-9][0-9A-Za-z._-]*\)}$/\1/p' "$repo_root/install.sh")
[ "$default" = "$tag" ] || { echo "install.sh default $default is not the built version $tag" >&2; exit 1; }
case "$(uname -m)" in x86_64|amd64) host=amd64; other=arm64 ;; aarch64|arm64) host=arm64; other=amd64 ;; *) echo "unsupported host" >&2; exit 1 ;; esac
real_uname=$(command -v uname)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/rel" "$work/inst"
fails=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1" >&2; fails=$((fails + 1)); }

cat > "$work/bin/curl" <<'FAKE'
#!/bin/sh
# Subset of curl used by install.sh and check-install-release.sh.
out=; want=0; url=
while [ $# -gt 0 ]; do
    case "$1" in
    -o) out=$2; shift ;;
    -w) want=1; shift ;;
    --proto|--retry|--connect-timeout|--max-time) shift ;;
    -*) ;;
    *) url=$1 ;;
    esac
    shift
done
printf '%s\n' "$url" >> "$FAKE_LOG"
prefix=https://github.com/VAR7IANT/Rout/releases/download/
case "$url" in
"$prefix"*) ;;
*) echo "fake curl: unexpected URL $url" >&2; exit 6 ;;
esac
file=$FAKE_RELEASES/${url#"$prefix"}
if [ -f "$file" ]; then code=200; [ "$out" = /dev/null ] || cp "$file" "$out"; else code=404; [ "$out" = /dev/null ] || echo 'Not Found' > "$out"; fi
[ "$want" = 0 ] || printf '%s' "$code"
exit 0
FAKE
cat > "$work/bin/uname" <<FAKE
#!/bin/sh
[ "\${FAKE_ARCH:-}" ] && [ "\$1" = -m ] && { echo "\$FAKE_ARCH"; exit 0; }
exec $real_uname "\$@"
FAKE
chmod +x "$work/bin/curl" "$work/bin/uname"

publish() { # publish TAG: both binaries, version.txt and checksums.txt from dist
    mkdir -p "$work/rel/$1"
    cp "$dist/rout-linux-amd64" "$dist/rout-linux-arm64" "$dist/version.txt" "$dist/checksums.txt" "$work/rel/$1/"
}
fake_release() { # fake_release TAG VERSION-OUTPUT: a script binary for both arches with a valid checksum
    mkdir -p "$work/rel/$1"
    for a in amd64 arm64; do printf '#!/bin/sh\necho "%s"\n' "$2" > "$work/rel/$1/rout-linux-$a"; done
    (cd "$work/rel/$1" && sha256sum rout-linux-amd64 rout-linux-arm64 > checksums.txt)
}
install_old() { rm -rf "$work/inst"; mkdir -p "$work/inst"; printf '#!/bin/sh\necho "rout old"\n' > "$work/inst/rout"; chmod 755 "$work/inst/rout"; cp "$work/inst/rout" "$work/old.copy"; }
run() { # run [VAR=value...]: the real install.sh, fake curl/uname first on PATH
    : > "$work/log"
    env PATH="$work/bin:$PATH" FAKE_LOG="$work/log" FAKE_RELEASES="$work/rel" ROUT_INSTALL_DIR="$work/inst" "$@" sh "$repo_root/install.sh" > "$work/out" 2>&1
}
untouched() { cmp -s "$work/inst/rout" "$work/old.copy" && [ "$(ls -A "$work/inst" | wc -l)" = 1 ]; }
only_release_urls() { [ -s "$work/log" ] && ! grep -v '^https://github.com/VAR7IANT/Rout/releases/download/' "$work/log" >/dev/null; }

# 1. A published release installs: right file names, SHA256 verified, version checked, atomic.
publish "$tag"; install_old
if run && cmp -s "$work/inst/rout" "$dist/rout-linux-$host" && [ "$("$work/inst/rout" version)" = "rout ${tag#v}" ] && [ "$(stat -c %a "$work/inst/rout")" = 755 ] && [ "$(ls -A "$work/inst" | wc -l)" = 1 ] &&
    [ "$(cat "$work/log")" = "https://github.com/VAR7IANT/Rout/releases/download/$tag/rout-linux-$host
https://github.com/VAR7IANT/Rout/releases/download/$tag/checksums.txt" ]; then ok "published $tag installs $host (names, SHA256, version, atomic replace, no leftovers)"; else bad "published release did not install cleanly"; cat "$work/out" >&2; fi

# 2. The other architecture: the right asset name is requested and its SHA256 verified. It can
#    only run where that architecture can execute, so a failure after verification is fine.
install_old
run FAKE_ARCH="$( [ "$other" = arm64 ] && echo aarch64 || echo x86_64 )" || true
if grep -q "/download/$tag/rout-linux-$other\$" "$work/log" && grep -q "/download/$tag/checksums.txt\$" "$work/log" && grep -q 'OK$' "$work/out" && { cmp -s "$work/inst/rout" "$dist/rout-linux-$other" || untouched; }; then ok "$other: asset name and SHA256 verified"; else bad "$other asset not requested/verified"; cat "$work/out" >&2; fi

# 3. A release that is not published: explicit message, nothing changed, no other version tried.
rm -rf "$work/rel/$tag"; install_old
if ! run && untouched && grep -q "is not published yet (HTTP 404)" "$work/out" && only_release_urls && ! grep -v "/download/$tag/" "$work/log" >/dev/null; then ok "unpublished $tag: HTTP 404 named, installation untouched, no fallback to another version"; else bad "unpublished release not handled"; cat "$work/out" >&2; fi

# 4. A tampered binary: SHA256 mismatch keeps the existing installation.
publish "$tag"; printf 'tamper' >> "$work/rel/$tag/rout-linux-$host"; install_old
if ! run && untouched && grep -q 'FAILED' "$work/out"; then ok "tampered binary rejected, installation untouched"; else bad "tampered binary accepted"; cat "$work/out" >&2; fi

# 5. A checksum entry that is missing or ambiguous is refused.
publish "$tag"; grep -v "rout-linux-$host" "$work/rel/$tag/checksums.txt" > "$work/c" && cp "$work/c" "$work/rel/$tag/checksums.txt"; install_old
if ! run && untouched; then ok "missing checksum entry rejected"; else bad "missing checksum accepted"; fi
publish "$tag"; cat "$dist/checksums.txt" "$dist/checksums.txt" > "$work/rel/$tag/checksums.txt"; install_old
if ! run && untouched; then ok "duplicate checksum entry rejected"; else bad "duplicate checksum accepted"; fi

# 6. A binary whose checksum is right but whose version is not the requested one is refused.
rm -rf "$work/rel/$tag"; fake_release "$tag" "rout 9.9.9"; install_old
if ! run && untouched && grep -q 'version mismatch' "$work/out"; then ok "binary of another version rejected, installation untouched"; else bad "version mismatch accepted"; cat "$work/out" >&2; fi

# 7. ROUT_VERSION pins another published version (its own URLs, its own version check).
fake_release v0.0.1 "rout 0.0.1"; install_old
if run ROUT_VERSION=v0.0.1 && [ "$("$work/inst/rout" version)" = "rout 0.0.1" ] && grep -q '/download/v0.0.1/' "$work/log" && ! grep -q "/download/$tag/" "$work/log"; then ok "ROUT_VERSION pin installs exactly that release"; else bad "ROUT_VERSION pin"; cat "$work/out" >&2; fi
install_old
if ! run 'ROUT_VERSION=v1;rm -rf /' && untouched && grep -q 'Invalid version' "$work/out"; then ok "malformed ROUT_VERSION rejected before any download"; else bad "malformed ROUT_VERSION"; fi

# 8. The release-order check: only a missing release is an error, and only on main.
check() { # check EVENT REF -> exit status
    : > "$work/log"
    env PATH="$work/bin:$PATH" FAKE_LOG="$work/log" FAKE_RELEASES="$work/rel" GITHUB_EVENT_NAME="$1" GITHUB_REF="$2" sh "$here/check-install-release.sh" > "$work/out" 2>&1
}
rm -rf "$work/rel/$tag"
if check push refs/heads/main; then bad "check: an unpublished release on main passed"; else grep -q '::error' "$work/out" && ok "check: unpublished release on main fails (installer window is open)"; fi
if check pull_request refs/pull/1/merge && grep -q '::warning' "$work/out"; then ok "check: unpublished release on a pull request warns only"; else bad "check: pull request"; fi
if check push refs/tags/"$tag"; then ok "check: tag build skipped (the release job publishes it)"; else bad "check: tag build"; fi
publish "$tag"
if check push refs/heads/main && grep -q 'is published' "$work/out"; then ok "check: published release passes on main"; else bad "check: published release"; fi

[ "$fails" = 0 ] || { echo "$fails check(s) failed" >&2; exit 1; }
echo "install.sh checks passed"
