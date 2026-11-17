#!/usr/bin/env bash
# Reversible debloat for the onn 4K Plus (coffey).
#
# Uses `pm uninstall --user 0` (falls back to `pm disable-user`), which removes
# the app for the user without touching the read-only system partition.
# Restore records distinguish uninstalled and disabled apps; legacy records work too.
#
# Usage:
#   tools/coffey-debloat.sh --list
#   tools/coffey-debloat.sh --apply-safe [--yes]
#   tools/coffey-debloat.sh --remove "pkg1 pkg2 ..." [--yes]
#   tools/coffey-debloat.sh --restore work/debloat/removed-YYYYmmdd-HHMMSS.txt
#   tools/coffey-debloat.sh --set-home projectivy|stock
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERIAL=""
YES=0
ACTION=""
ARG=""
RECORD_DIR="$REPO/work/debloat"

CRITICAL="
com.google.android.gms com.android.vending com.google.android.gsf
com.google.android.webview com.google.android.permissioncontroller
com.android.tv.settings com.droidlogic.tv.settings com.android.systemui
com.android.providers.settings com.android.providers.media
com.android.providers.media.module com.android.providers.downloads
com.android.providers.tv com.android.externalstorage com.android.networkstack
com.android.networkstack.tethering com.android.bluetooth com.android.wifi.resources
com.android.keychain com.android.certinstaller com.android.packageinstaller
com.google.android.packageinstaller com.android.shell com.android.inputdevices
com.google.android.inputmethod.latin com.android.location.fused
com.google.android.tv.axel com.google.android.tv.remote.service
com.google.android.tv.dfuservice com.droidlogic.android.tv.connecteddevices
com.droidlogic.mictoggle com.gretzky.GlobalKey com.gretzky.hwinfo
com.onn.bluetoothconnect com.onn.btpairoverlay com.onn.updatenotification
com.android.rkpdapp com.android.se com.android.dynsystem
com.google.android.apps.tv.launcherx com.spocky.projengmenu
tv.projectivy.plugin.wallpaperprovider.overflight
"

# Low-risk system bloat: no boot/Play/DRM/remote dependency.
SAFE="
com.google.android.feedback
com.android.tv.feedbackconsent
com.android.cts.ctsshim
com.android.cts.priv.ctsshim
com.android.printspooler
com.android.soundpicker
com.android.htmlviewer
com.android.wallpaperbackup
com.android.sharedstoragebackup
com.android.backupconfirm
com.android.localtransport
com.android.managedprovisioning
com.android.devicelockcontroller
com.android.nearby.halfsheet
com.android.uwb.resources
com.android.virtualmachine.res
android.autoinstalls.config.soc.amlogic
"

# User-facing / optional: remove only if you do not use them.
OPTIONAL="
com.google.android.play.games
com.google.android.youtube.tvmusic
com.google.android.youtube.tv
com.google.android.syncadapters.calendar
com.google.android.apps.tv.dreamx
com.google.android.katniss
com.google.android.apps.mediashell
com.netflix.ninja
com.netflix.tokenmanager
"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --serial) SERIAL=${2:?}; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --list) ACTION=list; shift ;;
    --apply-safe) ACTION=safe; shift ;;
    --remove) ACTION=remove; ARG=${2:?}; shift 2 ;;
    --restore) ACTION=restore; ARG=${2:?}; shift 2 ;;
    --set-home) ACTION=home; ARG=${2:?}; shift 2 ;;
    --private-dns) ACTION=dns; ARG=${2:?}; shift 2 ;;
    --disable-stock-launcher) ACTION=disablelauncher; shift ;;
    --enable-stock-launcher) ACTION=enablelauncher; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[ -n "$ACTION" ] || { usage; exit 2; }

ADB=(adb)
[ -n "$SERIAL" ] && ADB+=(-s "$SERIAL")
sh_dev() { "${ADB[@]}" shell "$@"; }
say() { printf '[*] %s\n' "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

"${ADB[@]}" get-state >/dev/null 2>&1 || die "no adb device"
DEV=$(sh_dev getprop ro.product.device | tr -d '\r')
[ "$DEV" = coffey ] || die "device is '$DEV', not coffey"

is_critical() {
  local package
  for package in $CRITICAL; do
    [ "$package" = "$1" ] && return 0
  done
  return 1
}
installed() { sh_dev "pm list packages --user 0 2>/dev/null" | grep -qx "package:$1"; }

case "$ACTION" in
  list)
    echo "== safe system list =="
    for p in $SAFE; do installed "$p" && echo "  $p"; done
    echo
    echo "== optional (remove only if unused) =="
    for p in $OPTIONAL; do installed "$p" && echo "  $p"; done
    echo
    echo "== third-party apps (choose what to keep) =="
    sh_dev 'pm list packages -3' | sed 's/package://' | sort
    echo
    echo "== critical (never removed by this tool) =="
    for p in $CRITICAL; do echo "  $p"; done
    ;;

  safe)
    if [ "$YES" != 1 ]; then
      printf 'Remove the %s packages in the safe list? [y/N] ' "$(echo $SAFE | wc -w | tr -d ' ')"
      read -r ans; case "$ans" in y|Y|yes) ;; *) exit 1 ;; esac
    fi
    mkdir -p "$RECORD_DIR"
    REC="$RECORD_DIR/removed-$(date +%Y%m%d-%H%M%S).txt"
    : > "$REC"
    for p in $SAFE; do
      if ! installed "$p"; then say "$p already absent"; continue; fi
      if is_critical "$p"; then say "$p is critical; skipped"; continue; fi
      if sh_dev "pm uninstall --user 0 $p" >/dev/null 2>&1; then
        say "uninstalled $p"
        operation=uninstalled
      elif sh_dev "pm disable-user --user 0 $p" >/dev/null 2>&1; then
        say "disabled $p"
        operation=disabled
      else
        say "FAILED $p"; continue
      fi
      printf '%s %s\n' "$p" "$operation" >> "$REC"
    done
    say "record: $REC"
    say "restore: tools/coffey-debloat.sh --restore $REC"
    ;;

  remove)
    if [ "$YES" != 1 ]; then
      printf 'Remove: %s ? [y/N] ' "$ARG"
      read -r ans; case "$ans" in y|Y|yes) ;; *) exit 1 ;; esac
    fi
    mkdir -p "$RECORD_DIR"
    REC="$RECORD_DIR/removed-$(date +%Y%m%d-%H%M%S).txt"
    : > "$REC"
    for p in $ARG; do
      if is_critical "$p"; then say "$p is critical; skipped"; continue; fi
      if ! installed "$p"; then say "$p already absent"; continue; fi
      if sh_dev "pm uninstall --user 0 $p" >/dev/null 2>&1; then
        say "uninstalled $p"
        operation=uninstalled
      elif sh_dev "pm disable-user --user 0 $p" >/dev/null 2>&1; then
        say "disabled $p"
        operation=disabled
      else
        say "FAILED $p"; continue
      fi
      printf '%s %s\n' "$p" "$operation" >> "$REC"
    done
    say "record: $REC"
    ;;

  restore)
    [ -f "$ARG" ] || die "no such record: $ARG"
    failed=0
    while read -r p operation || [ -n "$p" ]; do
      [ -n "$p" ] || continue
      [[ "$p" =~ ^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$ ]] || die "invalid package in record: $p"
      case "$operation" in
        disabled) restore="pm enable --user 0 $p" ;;
        uninstalled) restore="pm install-existing --user 0 $p" ;;
        '') restore="pm install-existing --user 0 $p && pm enable --user 0 $p" ;;
        *) die "unknown operation in record: $operation" ;;
      esac
      if sh_dev "$restore" >/dev/null 2>&1; then
        say "restored $p"
      else
        say "could not restore $p (reinstall from Play/APK)"
        failed=1
      fi
    done < "$ARG"
    exit "$failed"
    ;;

  home)
    case "$ARG" in
      projectivy)
        sh_dev 'cmd package set-home-activity com.spocky.projengmenu/.ui.home.MainActivity'
        ;;
      stock)
        sh_dev 'cmd package set-home-activity com.google.android.apps.tv.launcherx/.home.HomeActivity'
        ;;
      *) die "home must be 'projectivy' or 'stock'" ;;
    esac
    sh_dev 'cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME'
    ;;

  dns)
    case "$ARG" in
      off|none)
        sh_dev 'settings put global private_dns_mode off' || \
          die "could not set Private DNS from adb; use Settings > Network > Private DNS"
        ;;
      *)
        sh_dev "settings put global private_dns_mode hostname" && \
        sh_dev "settings put global private_dns_specifier $ARG" || \
          die "could not set Private DNS from adb; use Settings > Network > Private DNS"
        ;;
    esac
    say "private_dns_mode=$(sh_dev 'settings get global private_dns_mode' | tr -d '\r')"
    say "private_dns_specifier=$(sh_dev 'settings get global private_dns_specifier' | tr -d '\r')"
    ;;

  disablelauncher)
    res=$(sh_dev 'cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME' | tr -d '\r')
    case "$res" in
      *com.spocky.projengmenu*)
        ;;
      *)
        die "Projectivy is not the default HOME yet. Set it in TV Settings > Apps > Default apps > Home app (or Projectivy's 'set as default launcher'), then rerun."
        ;;
    esac
    if sh_dev "pm disable-user --user 0 com.google.android.apps.tv.launcherx" >/dev/null 2>&1; then
      say "stock Google TV launcher disabled (fallback: --enable-stock-launcher)"
    elif sh_dev "pm uninstall --user 0 com.google.android.apps.tv.launcherx" >/dev/null 2>&1; then
      say "stock Google TV launcher uninstalled for user 0 (restore: --enable-stock-launcher)"
    else
      die "could not disable the stock launcher"
    fi
    ;;

  enablelauncher)
    sh_dev "pm install-existing --user 0 com.google.android.apps.tv.launcherx" >/dev/null 2>&1 || true
    sh_dev "pm enable com.google.android.apps.tv.launcherx" >/dev/null 2>&1 || true
    say "stock launcher re-enabled; press HOME"
    ;;
esac
