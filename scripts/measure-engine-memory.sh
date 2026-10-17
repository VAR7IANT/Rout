#!/bin/sh
# Install the pinned engines inside a memory-limited cgroup and report what the kernel saw.
#
#   sudo sh scripts/measure-engine-memory.sh LIMIT_MIB ROUT_BINARY [WORKDIR]
#
# Example (approximate a 1 GB VPS with other services running):
#   sudo sh scripts/measure-engine-memory.sh 128 ./rout-linux-amd64
#
# It needs root and a writable cgroup v1 (memory controller) or cgroup v2 hierarchy, and
# downloads the real engines. It never touches /etc/rout or /opt/rout: state and engines go
# to a fresh directory under WORKDIR (default: a new mktemp directory, removed afterwards).
# Output: exit status, peak cgroup usage (page cache included), the number of times the limit
# was hit, and the number of OOM kills. Exit status 0 means the install succeeded within the limit.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 LIMIT_MIB ROUT_BINARY [WORKDIR]" >&2; exit 2; }
LIMIT_MIB=$1
BIN=$(readlink -f "$2")
case "$LIMIT_MIB" in ''|*[!0-9]*) echo 'LIMIT_MIB must be a number' >&2; exit 2 ;; esac
[ -x "$BIN" ] || { echo "not executable: $BIN" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo 'run as root (cgroup writes)' >&2; exit 2; }

if [ $# -ge 3 ]; then WORK=$(mkdir -p "$3" && readlink -f "$3")/run-$$; mkdir "$WORK"; else WORK=$(mktemp -d); fi
LIMIT=$((LIMIT_MIB * 1024 * 1024))
NAME=rout-measure-$$
CG=
cleanup() { [ -z "$CG" ] || rmdir "$CG" 2>/dev/null || true; rm -rf -- "$WORK"; }
trap cleanup EXIT HUP INT TERM
unusable() { echo "cannot use cgroup memory limits here: $1" >&2; exit 2; }

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    MODE=v2
    ROOT=/sys/fs/cgroup
    echo +memory > "$ROOT/cgroup.subtree_control" 2>/dev/null || true
    CG=$ROOT/$NAME
    mkdir "$CG" 2>/dev/null || { CG=; unusable 'cannot create a cgroup'; }
    echo "$LIMIT" > "$CG/memory.max" 2>/dev/null || unusable 'the memory controller is not enabled'
    echo 0 > "$CG/memory.swap.max" 2>/dev/null || true
elif [ -d /sys/fs/cgroup/memory ]; then
    MODE=v1
    CG=/sys/fs/cgroup/memory/$NAME
    mkdir "$CG" 2>/dev/null || { CG=; unusable 'cannot create a cgroup'; }
    echo "$LIMIT" > "$CG/memory.limit_in_bytes" 2>/dev/null || unusable 'cannot set the limit'
else
    unusable 'no cgroup memory controller found'
fi

echo "cgroup $MODE limit=${LIMIT_MIB}MiB binary=$BIN"
set +e
sh -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' sh "$CG" \
    "$BIN" --home "$WORK/home" --bin-dir "$WORK/bin" --service none engines
RC=$?
set -e

if [ "$MODE" = v2 ]; then
    PEAK=$(cat "$CG/memory.peak" 2>/dev/null || echo unknown)
    HITS=$(awk '$1 == "max" { print $2 }' "$CG/memory.events")
    KILLS=$(awk '$1 == "oom_kill" { print $2 }' "$CG/memory.events")
else
    PEAK=$(cat "$CG/memory.max_usage_in_bytes")
    HITS=$(cat "$CG/memory.failcnt")
    KILLS=$(awk '$1 == "oom_kill" { print $2 }' "$CG/memory.oom_control")
fi
case "$PEAK" in ''|*[!0-9]*) PEAK_MIB=unknown ;; *) PEAK_MIB=$((PEAK / 1048576)) ;; esac
echo "exit=$RC peak_cgroup_MiB=$PEAK_MIB limit_hits=${HITS:-0} oom_kills=${KILLS:-0}"
ls -l "$WORK/bin" 2>/dev/null | sed 's/^/  /' || true
exit "$RC"
