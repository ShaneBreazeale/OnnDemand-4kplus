# Backup and recovery

OnnDemand provides temporary administrative access. It does not provide an
automated, validated full-device restore procedure for the onn. 4K Plus.

## Before maintenance

- Use each application's supported export or backup feature where available.
- Copy important recordings, downloads, and exported settings off-device.
- Keep a note of the installed firmware build and the changes you intend to make.
- Store backups separately from the TV device and protect their contents.

App-private data can contain account tokens, provider details, and personal
information. Do not upload backup archives or database contents to repository
issues or pull requests.

## What a backup proves

A checksum can confirm that a captured file has not changed. It does not prove
that every needed file was captured, that an app's databases were consistent,
or that the data can be restored successfully.

Copies taken while apps are running can be incomplete or inconsistent. App
exports are preferable to manually copying live application state. If you make
manual copies, record the method, scope, firmware, and any reported failures.
Keep the original archive intact while testing a restoration on a separate copy.

A downloaded stock firmware archive is not a backup of your device's apps,
accounts, settings, or device-specific data. A raw partition image is not an
application-level restore plan.

## Restoring files and app settings

Use the app's own import or restore feature first. Ordinary shared-storage
files can be copied back to their appropriate locations.

App-private data requires application-specific handling. Ownership, Android
user profiles, filesystem labels, encryption, and app versions can differ
between installations. Do not reuse another device's identifiers or apply a
single ownership or labeling recipe to every app.

The standalone backup utilities in this checkout have their own root-session
requirements. They are not an automatic backup stage of `onndemand`, and an
SSH root shell does not imply that `adb root` or another root interface exists.

## Interrupted operations

If an SSH command times out, it may still be running. Inspect its state before
retrying. Do not delete an operation lock or repeat a write solely because the
host connection was lost.

Rebooting ends temporary root and stops SSH. It does not undo app removals,
file writes, or settings changes already completed. Restore those using the
relevant application's or tool's documented method.

## Recovery limits

A backup alone does not establish a working recovery transport. The inactive
boot slot is not a proven fallback. OnnDemand does not validate bootloader
unlocking, permanent-root installation, or firmware restoration for the 4K Plus.

If Android no longer starts after a modification, preserve the backup and
operation records. Use an established recovery procedure for the exact device
and firmware; do not experiment with unrelated images or slot changes.

For normal session startup and shutdown, see the
[temporary root guide](ROOT_PATH.md).
