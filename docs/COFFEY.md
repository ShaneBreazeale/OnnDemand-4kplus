# Device setup and compatibility

OnnDemand's supported workflow is temporary root and SSH on the onn. 4K Plus.

| Item | Tested configuration |
| --- | --- |
| Device | onn. 4K Plus, codename `coffey` |
| Android | 14 |
| Firmware build | `URO4.260304.011.B1` / `15051976` |
| Default helper architecture | ARM64 |
| Host systems | macOS and Linux with Bash |
| Measured connection | Authorized USB ADB, with SSH forwarded over ADB |

The ARMv7 SSH helper can be built, but was not exercised on the device during
the recorded SSH tests. Direct LAN SSH and every other firmware version have
not been validated by those tests.

The older 4K Pro (`jarvis2`) instructions and profiles retained in this checkout
are legacy material. They are not installation instructions for the 4K Plus.

## Prepare ADB

1. Enable developer options and USB debugging in the TV's Android settings.
2. Connect the host and accept the debugging authorization prompt on the TV.
3. Run `adb devices -l` and identify the intended device.
4. Confirm that the device shows `device`, not `unauthorized` or `offline`.

An already configured network ADB connection can also be selected. Network
setup varies by firmware; do not assume enabling USB debugging makes the device
available over the network.

From the host, confirm the device and firmware:

```sh
adb -s DEVICE_TARGET shell getprop ro.product.device
adb -s DEVICE_TARGET shell getprop ro.build.version.incremental
```

Replace `DEVICE_TARGET` with the exact ADB transport. The expected results are
`coffey` and `15051976`. OnnDemand performs additional checks before a new root
attempt.

## Start OnnDemand

Follow the [temporary root guide](ROOT_PATH.md), then use the connection
instructions printed by the CLI. The default SSH listener is device-local and
is reached through an authorized ADB forward.

## Unsupported configurations

Do not copy the 4K Pro firmware profile, change device checks, or select another
boot slot to make an unsupported build appear compatible. Report the model,
firmware build, tool version, and sanitized error instead.

The compatibility record does not certify streaming services, guarantee DRM
behavior, or establish an automated restore procedure. Keep important backups
independently of the device. See [backup and recovery](RESTORE.md).
