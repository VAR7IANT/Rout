#!/bin/sh
set -eu
umask 077

REPO=VAR7IANT/Rout
VERSION=${ROUT_VERSION:-v0.1.0}
DEST=${ROUT_INSTALL_DIR:-/usr/local/bin}

fail() { printf '%s\n' "错误：$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail '仅支持 Linux'
[ "$(id -u)" = 0 ] || fail '请以 root 运行，或先下载脚本再使用 sudo sh install.sh'
case "$VERSION" in *[!a-zA-Z0-9._-]*|'') fail '版本号无效' ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) fail '仅支持 amd64／arm64' ;; esac

if ! command -v curl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates coreutils
    elif command -v apt-get >/dev/null 2>&1; then apt-get update; apt-get install -y curl ca-certificates coreutils
    else fail '请先安装 curl、CA 证书和 sha256sum'; fi
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
ASSET=rout-linux-$ARCH
BASE=https://github.com/$REPO/releases/download/$VERSION
printf '%s\n' "下载 Rout $VERSION ($ARCH)…"
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 180 "$BASE/$ASSET" -o "$TMP/$ASSET"
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 60 "$BASE/checksums.txt" -o "$TMP/checksums.txt"
HASH=$(awk -v name="$ASSET" '$2 == name || $2 == "*"name { print $1 }' "$TMP/checksums.txt")
[ "${#HASH}" = 64 ] || fail '没有找到唯一有效的 SHA256 校验值'
printf '%s  %s\n' "$HASH" "$TMP/$ASSET" | sha256sum -c - || fail '校验失败，保留原安装'
chmod 755 "$TMP/$ASSET"
"$TMP/$ASSET" version
mkdir -p "$DEST"
# Copy inside the destination filesystem before renaming atomically.
STAGED=$DEST/.rout-install-$$
trap 'rm -rf "$TMP"; rm -f "$STAGED"' EXIT HUP INT TERM
cp "$TMP/$ASSET" "$STAGED"
chmod 755 "$STAGED"
mv -f "$STAGED" "$DEST/rout"
printf '%s\n' '安装完成，输入 rout 打开中文菜单' '首次创建节点或中转时自动下载并校验所需内核'
