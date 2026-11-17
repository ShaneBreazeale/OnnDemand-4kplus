# Temporary root guide

OnnDemand provides temporary administrative access for maintenance on the
onn. 4K Plus (`coffey`). The tested firmware is Android 14 build **15051976**
(`URO4.260304.011.B1`). Other devices and firmware versions are unsupported.

The workflow keeps the existing boot configuration. It does not unlock the
bootloader, replace boot images, or require a factory reset. Permanent root
and bootloader unlocking on the 4K Plus are outside the supported workflow.

## Before starting

- Use a macOS or Linux host with Bash, uv, ADB, and an SSH client.
- Authorize the host's ADB connection on the TV.
- Export important app settings and keep copies of files you need off-device.
- Read [device setup and compatibility](COFFEY.md).

From a checkout, install the CLI:

```sh
uv tool install .
onndemand --version
adb devices -l
```

Use the serial or network address shown by `adb devices` wherever
`DEVICE_TARGET` appears below. The selected device must show `device`, rather
than `unauthorized` or `offline`.

## Start a session

```sh
onndemand --target DEVICE_TARGET
```

The CLI checks the device, prepares authentication, and requests confirmation
before a new root attempt. It then starts SSH and prints connection instructions
and the device's SSH host-key fingerprint. Use those instructions to connect,
and compare the fingerprint before accepting a new host identity.

The default authentication is an existing or newly generated SSH key. Password
and combined authentication options are described in the [SSH guide](SSH.md).

To reuse an already running compatible temporary-root session:

```sh
onndemand --target DEVICE_TARGET --skip-root
```

A running SSH server must be stopped before its authentication is reconfigured.

## During the session

Check the identity of a connected SSH shell with:

```sh
id -u
```

Successful administrative access reports `0`. This confirms the current shell's
identity; it does not establish compatibility with every Android service.

The shell supports filesystem maintenance and ordinary shell commands. Some
Android framework operations are unavailable in this context. Use the normal
authorized ADB shell for app-management and settings commands that require it.

## Security effects and persistence

Temporary root reduces runtime security protections. The current workflow
relaxes SELinux enforcement and kernel module verification for the rooted boot.
A locked bootloader or a normal boot-state report does not mean those runtime
protections remain unchanged.

Authenticated SSH clients have administrative control of the device. Keep
access on a trusted connection and end the rooted session when maintenance is
complete. Stopping SSH closes the server; it does not undo temporary root or
restore the runtime protections changed by the root operation.

Reboot the device to end temporary root and stop SSH. The tool does not install
an automatic startup service. Its saved server files, authentication settings,
and host identity remain on disk. Files, apps, and settings you deliberately
change can also persist after reboot.

## Failed or interrupted operations

A root attempt can fail, crash, or reboot the device. If a command times out or
its result is uncertain, inspect the current state before retrying. Do not
remove an operation lock while its command may still be running.

If the device reboots, wait for Android to finish starting and reauthorize ADB
if necessary. A firmware mismatch requires a separately validated release;
changing a profile or bypassing a check is not a supported workaround.

The tested results are limited to one device and firmware build. Streaming
compatibility, playback quality, successful restoration, and recovery from a
failed operation are not guaranteed. See [backup and recovery](RESTORE.md) and
the [SSH troubleshooting guide](SSH.md#troubleshooting).

For support, provide the model, firmware build, OnnDemand version, and a
sanitized error message. Keep device identifiers, credentials, and private
backups out of reports. Source attribution and licenses are in
[THIRD_PARTY.md](../THIRD_PARTY.md).
