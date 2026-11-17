#!/usr/bin/env bash
# Run one command through the coffey temporary-root loop.
# Framework commands (pm/am/cmd/dumpsys) require the normal adb shell.
# Binary stdout and stderr are returned separately, with the command's exit code.
# Usage:
#   tools/coffey-sudo.sh 'id; ls /data'
#   tools/coffey-sudo.sh 'tar -C /data -cf - .' > data.tar
#   tools/coffey-sudo.sh --timeout 600 'long-command'
set -euo pipefail

RT=/data/local/tmp/rt
SERIAL=""
TIMEOUT=120
usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --serial) SERIAL=${2:?}; shift 2 ;;
    --timeout) TIMEOUT=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown arg: $1" ;;
    *) break ;;
  esac
done
[[ "$TIMEOUT" =~ ^[1-9][0-9]{0,5}$ ]] || die "timeout must be a positive integer (at most 999999 seconds)"
ADB=(adb)
[ -n "$SERIAL" ] && ADB+=(-s "$SERIAL")
if [ $# -gt 0 ]; then CMD="$*"; else CMD=$(cat); fi
[ -n "$CMD" ] || die "empty command"
"${ADB[@]}" get-state >/dev/null 2>&1 || die "no adb device"
"${ADB[@]}" shell 'ps -A -o ARGS 2>/dev/null | grep -q "[s]h /data/local/tmp/rt/ksu_loader.sh"' \
  >/dev/null 2>&1 || die "root loop not running; run tools/coffey-root.sh first"

LOCAL=$(mktemp -d "${TMPDIR:-/tmp}/coffey-command.XXXXXXXX")
REQUEST="$RT/$(basename "$LOCAL")"
LOCK="$RT/command.lock"
locked=0
published=0
cleanup() {
  rm -rf "$LOCAL"
  if [ "$locked" = 1 ] && [ "$published" = 0 ]; then
    "${ADB[@]}" shell "rmdir '$LOCK'" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"${ADB[@]}" shell "mkdir '$LOCK'" >/dev/null 2>&1 || \
  die "another command is running or its result is uncertain; do not remove the lock while it may still run"
locked=1
"${ADB[@]}" shell "test ! -e '$RT/cmd' && test ! -e '$RT/cmd.run'" >/dev/null 2>&1 || \
  die "the root mailbox is busy; retry after its current command finishes"
"${ADB[@]}" shell "mkdir -m 777 '$REQUEST'" >/dev/null
printf '%s\n' "$CMD" > "$LOCAL/user.sh"
"${ADB[@]}" push "$LOCAL/user.sh" "$REQUEST/user.sh" >/dev/null
# The existing loader executes this wrapper. Results belong to this request;
# its private completion file is published only after both streams are closed.
cat > "$LOCAL/wrapper.sh" <<EOF_WRAPPER
umask 022
/system/bin/sh '$REQUEST/user.sh' > '$REQUEST/stdout' 2> '$REQUEST/stderr'
rc=\$?
printf '%s\\n' "\$rc" > '$REQUEST/status.tmp'
mv '$REQUEST/status.tmp' '$REQUEST/status'
rmdir '$LOCK'
EOF_WRAPPER
"${ADB[@]}" push "$LOCAL/wrapper.sh" "$REQUEST/wrapper.sh" >/dev/null
# From this point a transport failure cannot prove the command did not run.
# The wrapper owns lock release, including after a host timeout or disconnect.
published=1
"${ADB[@]}" shell "mv '$REQUEST/wrapper.sh' '$RT/cmd'" >/dev/null || \
  die "command publication is uncertain; inspect the mailbox before retrying"
end=$((SECONDS + TIMEOUT))
while [ "$SECONDS" -lt "$end" ]; do
  # exec-out uses the raw ADB protocol: remote failures can still return zero
  # and put diagnostics in stdout. Shell v2 preserves the status for polling;
  # adb pull preserves binary payloads and reports transfer failures.
  if "${ADB[@]}" shell -T cat "$REQUEST/status" > "$LOCAL/status" 2>/dev/null; then
    rc=$(cat "$LOCAL/status")
    [[ "$rc" =~ ^[0-9]{1,3}$ ]] && [ "$rc" -le 255 ] || die "invalid command status"
    "${ADB[@]}" pull "$REQUEST/stdout" "$LOCAL/stdout" >/dev/null 2>&1 || die "could not read command stdout"
    "${ADB[@]}" pull "$REQUEST/stderr" "$LOCAL/stderr" >/dev/null 2>&1 || die "could not read command stderr"
    cat "$LOCAL/stdout"
    cat "$LOCAL/stderr" >&2
    # The loader still owns cmd.run; remove only this request's result files.
    "${ADB[@]}" shell "rm -rf '$REQUEST'" >/dev/null 2>&1 || true
    exit "$rc"
  fi
  sleep 0.3
done
die "command timed out after ${TIMEOUT}s; it may still be running; results remain at $REQUEST"
