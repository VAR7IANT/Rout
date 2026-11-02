#!/bin/sh
set -eu
umask 022
mkdir -p dist
# A release must carry the management panel: refuse to build binaries around an empty embed.
if [ -f web/package.json ] && [ ! -f internal/webui/dist/index.html ]; then
    echo 'The web panel is not built: run (cd web && npm ci && npm run build) first' >&2
    exit 1
fi
version=$(sed -n 's/^const Version = "\([^"]*\)"/\1/p' internal/rout/model.go)
[ -n "$version" ] || { echo 'Cannot read Rout version' >&2; exit 1; }
printf 'v%s\n' "$version" > dist/version.txt
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags='-s -w' -o "dist/rout-linux-$arch" ./cmd/rout
done
(cd dist && sha256sum rout-linux-amd64 rout-linux-arm64 version.txt > checksums.txt && sha256sum -c checksums.txt)
