#!/bin/sh
set -eu
umask 077

REPO=VAR7IANT/Rout
VERSION=${ROUT_VERSION:-v0.3.6}
DEST=${ROUT_INSTALL_DIR:-/usr/local/bin}

fail() { printf '%s\n' "错误 / Error: $*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail '仅支持 Linux / Linux is required'
[ "$(id -u)" = 0 ] || fail '请使用 root 或 sudo sh install.sh / Run as root or use sudo sh install.sh'
case "$VERSION" in *[!a-zA-Z0-9._-]*|'') fail '版本号无效 / Invalid version' ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) fail '仅支持 amd64／arm64 / Only amd64/arm64 is supported' ;; esac

if ! command -v curl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then apk add --no-cache curl ca-certificates coreutils
    elif command -v apt-get >/dev/null 2>&1; then apt-get update; apt-get install -y curl ca-certificates coreutils
    else fail '请安装 curl、CA 证书和 sha256sum / Install curl, CA certificates and sha256sum'; fi
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
ASSET=rout-linux-$ARCH
BASE=https://github.com/$REPO/releases/download/$VERSION
printf '%s\n' "下载 / Downloading Rout $VERSION ($ARCH)..."
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 180 "$BASE/$ASSET" -o "$TMP/$ASSET"
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 60 "$BASE/checksums.txt" -o "$TMP/checksums.txt"
HASH=$(awk -v name="$ASSET" '$2 == name || $2 == "*"name { print $1 }' "$TMP/checksums.txt")
[ "${#HASH}" = 64 ] || fail '没有唯一有效的 SHA256 校验值 / A unique SHA256 checksum is required'
printf '%s  %s\n' "$HASH" "$TMP/$ASSET" | sha256sum -c - || fail '校验失败，保留原安装 / Checksum failed; keeping existing installation'
chmod 755 "$TMP/$ASSET"
ACTUAL_VERSION=$("$TMP/$ASSET" version)
[ "$ACTUAL_VERSION" = "rout ${VERSION#v}" ] || fail '文件版本与请求版本不一致，保留原安装 / Binary version mismatch; keeping existing installation'
printf '%s\n' "$ACTUAL_VERSION"
# Preserve the existing hash-only subscription database before replacing the manager.
# A disabled/unconfigured service remains disabled; no schema migration is required.
if [ "$DEST" = /usr/local/bin ]; then
    "$TMP/$ASSET" subscription prepare-upgrade || fail '订阅备份失败，保留旧安装 / Subscription backup failed; keeping existing installation'
fi
mkdir -p "$DEST"
# Copy inside the destination filesystem before renaming atomically.
STAGED=$DEST/.rout-install-$$
trap 'rm -rf "$TMP"; rm -f "$STAGED"' EXIT HUP INT TERM
cp "$TMP/$ASSET" "$STAGED"
chmod 755 "$STAGED"
mv -f "$STAGED" "$DEST/rout"
if [ "$DEST" = /usr/local/bin ] && [ "${ROUT_SETUP_TRAFFIC:-1}" = 1 ]; then
    if ! command -v nft >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then apk add --no-cache nftables
        elif command -v apt-get >/dev/null 2>&1; then apt-get update; apt-get install -y nftables
        fi
    fi
    if ! "$DEST/rout" traffic install; then
        printf '%s\n' '流量统计尚未启用；现有无限额节点继续运行。修复 nftables 后运行 rout traffic install / Traffic monitoring unavailable; unlimited nodes keep running. Fix nftables and run rout traffic install' >&2
    fi
fi
if [ "$DEST" = /usr/local/bin ]; then
    "$DEST/rout" subscription refresh || fail '订阅服务更新失败，原订阅和 Caddy 配置保留；运行 rout subscription refresh / Subscription refresh failed; data and Caddy preserved; run rout subscription refresh'
fi
printf '%s\n' '安装完成 / Installed. Run rout to select 简体中文 or English' '首次创建时自动校验所需内核 / Required engines are downloaded and verified on first use'
