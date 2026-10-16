#!/bin/sh
set -eu
mkdir -p dist
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags='-s -w' -o "dist/rout-linux-$arch" ./cmd/rout
done
(cd dist && sha256sum rout-linux-amd64 rout-linux-arm64 > checksums.txt)
