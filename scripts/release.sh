#!/bin/sh
set -eu
umask 022
mkdir -p dist
version=$(sed -n 's/^const Version = "\([^"]*\)"/\1/p' internal/rout/model.go)
[ -n "$version" ] || { echo 'Cannot read Rout version' >&2; exit 1; }
printf 'v%s\n' "$version" > dist/version.txt
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags='-s -w' -o "dist/rout-linux-$arch" ./cmd/rout
done
(cd dist && sha256sum rout-linux-amd64 rout-linux-arm64 version.txt > checksums.txt && sha256sum -c checksums.txt)
