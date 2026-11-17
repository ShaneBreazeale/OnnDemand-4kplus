# coffey restore runbook (post-unlock)

Scope: restore **TiviMate playlists/recordings**, **TV Quick Actions button
remaps**, and **launcher setup/customization** from the 2026-11-17 backup.
Assumes: bootloader unlocked, permanent root (Magisk/KernelSU), `/data`
freshly formatted (new FBE keys), device booted and `adb root` available.

Backup: `gpubox:~/onn-backup/coffey-FULL-20261117T053008Z`

---

## If you are not unlocking (temp-root-only)

You do **not** need the rest of this runbook. The backup is complete and the
device is unchanged; keeping the bootloader locked preserves Widevine L1.
For occasional root, run:

```sh
tools/coffey-root.sh --yes
tools/coffey-sudo.sh 'id; ls /data'
```

A reboot clears root; re-run the first command. The loop is a uid-0 process
with kernel SID: filesystem/block/process commands work, but `pm`/`am`/`cmd`/
`dumpsys` do not (use the normal adb shell for those). If you later unlock,
continue below.

---

## 0. Where everything is

| What | Archive path | Restore target |
|---|---|---|
| TiviMate CE data | `data/data-files.tar` → `./user/0/ar.tvplayer.tv/` (or `./data/ar.tvplayer.tv/`, same bind mount) | `/data/data/ar.tvplayer.tv` |
| TiviMate DE data | `data/data-files.tar` → `./user_de/0/ar.tvplayer.tv/` | `/data/user_de/0/ar.tvplayer.tv` |
| TiviMate DBs (clean) | `data/checkpointed/TvPlayer.db`, `TvgPrograms.db` | `/data/data/ar.tvplayer.tv/databases/` |
| TiviMate recordings | `data/data-files.tar` → `./media/0/Download/TiviMate/` | `/data/media/0/Download/TiviMate/` |
| TV Quick Actions | `./user/0/dev.vodik7.tvquickactions/` | `/data/data/dev.vodik7.tvquickactions` |
| Launcher (Google TV) | `./user/0/com.google.android.apps.tv.launcherx/` | `/data/data/com.google.android.apps.tv.launcherx` |
| onn launcher provider | `./user/0/com.droidlogic.launcher.provider/` | `/data/data/com.droidlogic.launcher.provider` |
| Projectivy wallpaper | `./user/0/tv.projectivy.plugin.wallpaperprovider.overflight/` | matching path |
| APKs | `apks/app/.../*.apk` | reinstall with `adb install` |
| Old uid/label map | `restore-metadata/restore-metadata.txt` | reference |

**Never restore `./user/10` from `data-files.tar`** — it was captured while
user 10 was FBE-locked (encrypted names). Use `data/user10-files.tar`.

**Pick one of `./data/<pkg>` and `./user/0/<pkg>`**, not both. They are the same
directory via a bind mount; restoring both just writes twice.

---

## 1. Reinstall the APKs first

Do not copy `/data/app` back: the random directory names and the uid mapping
change on a fresh install.

```sh
# TiviMate is a single base.apk in this backup
adb install -r apks/app/*/ar.tvplayer.tv-*/base.apk

# TV Quick Actions and launcher have splits
adb install-multiple apks/app/*/dev.vodik7.tvquickactions-*/*.apk
# the launcher is a system priv-app and is already present after wipe; only
# reinstall it if you replaced the system image
```

## 2. Map old uid -> new uid (critical)

Installing may assign a **different** app uid than the backup. Ask the device:

```sh
adb shell pm list packages -U | grep -E 'tvplayer|tvquickactions|launcherx'
# example old: tvplayer 10114, tvquickactions 10119, launcherx 10060
```

Use the **new** uid for every `chown`. The SELinux category is derived from
the new uid by `restorecon` (category = `uid - 10000`).

## 3. TiviMate (playlists, EPG, favorites, recordings)

The playlist row is plaintext in `TvPlayer.db` (name `operator2.barfik.org`,
plus 56,967 channels / 185,661 movies / 50,351 series), so it does not depend
on Android Keystore.

```sh
NEW=10114   # replace with the uid from step 2
adb shell am force-stop ar.tvplayer.tv

# push the checkpointed DBs (no WAL needed) and the prefs/files
adb push data/checkpointed/TvPlayer.db      /data/local/tmp/
adb push data/checkpointed/TvgPrograms.db   /data/local/tmp/
# extract the rest of the subtree from the tar on the host, then push:
#   user/0/ar.tvplayer.tv/{shared_prefs,files,no_backup}
adb shell 'mkdir -p /data/data/ar.tvplayer.tv/databases'
adb shell "cp /data/local/tmp/TvPlayer.db /data/local/tmp/TvgPrograms.db /data/data/ar.tvplayer.tv/databases/"
# ... copy shared_prefs / files / no_backup ...
adb shell "chown -R $NEW:$NEW /data/data/ar.tvplayer.tv"
adb shell "restorecon -RF /data/data/ar.tvplayer.tv"

# DE side (usually small)
adb shell 'mkdir -p /data/user_de/0/ar.tvplayer.tv'
# copy ./user_de/0/ar.tvplayer.tv/* from the tar, then:
adb shell "chown -R $NEW:$NEW /data/user_de/0/ar.tvplayer.tv"
adb shell "restorecon -RF /data/user_de/0/ar.tvplayer.tv"

# recordings (shared storage)
adb push <extracted media/0/Download/TiviMate> /data/media/0/Download/
adb shell 'chown -R media_rw:media_rw /data/media/0/Download/TiviMate'
adb shell 'restorecon -RF /data/media/0/Download/TiviMate'
```

Launch TiviMate once; the playlist and cached VOD/series should appear. If the
provider credentials in the URL are still valid, an update succeeds without
re-adding the playlist. TiviMate *premium/account* status may need a Play Store
or TiviMate account re-login — separate from the playlist data.

## 4. Launcher setup / customization

The Google TV launcher's **241 MB data dir is in the backup**, including
`files/AccountData.pb`, `AccountSyncData.pb`,
`OemOfflineCustomizationResponse.pb`, `LocalPackagesStore.pb`, and the
per-account UI databases (`uientity.db`, `channel_groups.db`, ...). The onn
`com.droidlogic.launcher.provider` data and the Projectivy wallpaper prefs are
also captured.

```sh
adb shell am force-stop com.google.android.apps.tv.launcherx
# copy ./user/0/com.google.android.apps.tv.launcherx/* over the existing dir
adb shell "chown -R 10060:10060 /data/data/com.google.android.apps.tv.launcherx"
adb shell "restorecon -RF /data/data/com.google.android.apps.tv.launcherx"

# onn customization provider (uid from step 2, old 10077)
adb shell am force-stop com.droidlogic.launcher.provider
# copy its data, chown, restorecon

# Projectivy wallpaper prefs (old uid 10121)
# copy shared_prefs, chown, restorecon
```

The launcher also syncs some layout from the signed-in Google account; signing
in with the same account may reconcile or override the local cache. The local
data still carries the onn customization and the per-account UI DBs.

## 5. TV Quick Actions (button remaps)

Remaps live in `databases/tvqa.db` (+ `files/datastore/*.preferences_pb`), not
in keylayout or settings.

```sh
adb shell am force-stop dev.vodik7.tvquickactions
# copy ./user/0/dev.vodik7.tvquickactions/{databases,files,shared_prefs}
adb shell "chown -R 10119:10119 /data/data/dev.vodik7.tvquickactions"   # new uid
adb shell "restorecon -RF /data/data/dev.vodik7.tvquickactions"
```

## 6. SELinux rules (do not skip)

1. `chown` **first**.
2. `restorecon -RF` **second** — it derives `app_data_file:s0:c<uid-10000>,
   c256,c512,c768` (or `privapp_data_file` for the launcher) from the new uid.
3. If `restorecon` does not add categories on this build:
   `chcon u:object_r:app_data_file:s0:c<newuid-10000>,c256,c512,c768 <dir>`
   for each app; launcher uses `privapp_data_file:s0:c512,c768`.

The tar has **no SELinux xattrs**, so `restorecon`/`chcon` is mandatory. The
reference labels are in `restore-metadata/labels.txt`.

## 7. Secondary profile (user 10) — optional

Recreate the TV profile (`pm create-user --profileOf 0 --managed ...` or match
`com.android.tv.profile`), `am start-user 10`, then restore
`user10-files.tar` (`user/10`, `user_de/10`, `media/10`,
`misc/profiles/cur/10`), chown to that profile's app uids (`10*100000 + appid`)
and `restorecon`. Skip if the profile is not important; reinstall apps fresh.

## 8. Verify

```sh
adb shell 'dmesg | grep -i avc'          # expect no new denials
# TiviMate: open, check the playlist, channel list, a VOD/series entry
# TV Quick Actions: press a remapped button
# Launcher: home layout / onn customization / wallpaper
```

## 9. What will NOT restore (re-setup, not backup failure)

- Android Keystore / TEE-backed secrets: Wi-Fi passwords, Bluetooth pairings
  (bt_config.conf is captured but may be key-wrapped), Google/account tokens,
  app logins that use AccountManager/Keystore.
- Widevine/DRM: provisioning is re-created, and **unlocking the bootloader
  commonly drops Widevine L1 permanently** — Netflix/DRM may fall to SD.
- The raw `partitions/userdata.img` is FBE ciphertext and is **not** a restore
  source after a wipe. Use the plaintext tars.

## 10. Rehearsal

Do a full rehearsal **after unlock, before trusting user 0**: restore TiviMate
into the secondary profile (user 10), launch it there, then repeat for user 0.
The host-side rehearsal is already done: all three DBs pass
`PRAGMA integrity_check` after WAL checkpoint, and all 119 APKs pass zip
integrity.
