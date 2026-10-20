#!/bin/sh
# Test-only core; never installed by Rout or included in Rout release assets.
set -eu
[ "$#" = 1 ] || { echo 'Usage: test-mihomo.sh DESTINATION' >&2; exit 1; }
dest=$1
archive=$dest.download.gz
trap 'rm -f "$archive"' EXIT HUP INT TERM
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --max-time 180 \
  https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-v1-v1.19.32.gz \
  -o "$archive"
# Matches GitHub's SHA256 asset digest for this exact published core.
printf '%s  %s\n' 306f81e723e60ce6b828899a6fe83e1d00e9ecefb2dc8d4d849312a5bc00efdc "$archive" | sha256sum -c -
gzip -dc "$archive" > "$dest"
chmod 755 "$dest"
"$dest" -v
