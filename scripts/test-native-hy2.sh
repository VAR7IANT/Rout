#!/bin/sh
# Test-only dependency. Not installed by Rout and not shipped in release assets.
set -eu
dest=$1
url=https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --max-time 180 "$url" -o "$dest"
printf '%s  %s\n' 907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691 "$dest" | sha256sum -c -
chmod 755 "$dest"
