# SSH access

OnnDemand starts an authenticated root SSH shell on the supported onn. 4K Plus
firmware. It supports interactive terminals and remote shell commands. SFTP and
SSH port forwarding are not implemented by the SSH helper.

Normal startup requests temporary root before starting SSH. The SSH helper does
not independently change the device's security settings, but the preceding root
operation reduces runtime protections. Read the
[temporary root guide](ROOT_PATH.md#security-effects-and-persistence) before use.

## Start

Use the exact authorized ADB serial or address shown by `adb devices -l`:

```sh
onndemand --target DEVICE_TARGET
```

OnnDemand prints the SSH host-key fingerprint and connection instructions.
Check the fingerprint before accepting a new host identity. The default
listener is device-local on port 2222.

Use `--skip-root` only when a compatible temporary-root session is already
running. Stop a running SSH server before changing its authentication settings.

## Authentication

| Mode | Accepted credentials |
| --- | --- |
| `--auth key` (default) | The selected public key |
| `--auth password` | A password entered at a hidden prompt |
| `--auth both` | Either the selected key OR the password |

`both` does not require two factors. Empty passwords and unauthenticated login
are refused. Passwords have no command-line argument or shared default. The
device stores a salted password verifier.

```sh
onndemand --target DEVICE_TARGET --public-key ~/.ssh/id_ed25519.pub
onndemand --target DEVICE_TARGET --auth password
onndemand --target DEVICE_TARGET --auth both
```

### Key selection

The tool chooses a client key in this order:

1. Explicit `--public-key` files.
2. Its previously saved key pair.
3. A standard key pair in `~/.ssh`: Ed25519, ECDSA, then RSA.
4. A newly generated Ed25519 pair, saved for future use.

Automatic discovery requires both public and private files. Agent-only keys can
be selected by supplying their public file explicitly. Only the public key is
sent to the device. Existing private keys are not copied or read by the setup
tool.

Generated private keys have no passphrase. They are saved with mode 600 in a
mode 700 directory. To use a passphrase-protected or separately managed key,
supply its public file. Keep the selected private key while you still need to
connect. Password-only mode does not generate a key.

Keys with authorized_keys restrictions are rejected rather than having their
restrictions silently discarded. Repeat `--public-key` to select multiple files.

## Connect through ADB

Forward a local port through the authorized ADB connection:

```sh
adb -s DEVICE_TARGET forward tcp:2222 tcp:2222
```

Then use the SSH command printed by OnnDemand, including its selected identity.
If you supplied a public key explicitly, select the matching private key in
your SSH client:

```sh
ssh -i PATH_TO_SELECTED_PRIVATE_KEY -p 2222 root@127.0.0.1
```

If port 2222 is already in use on the host, choose another local port in the
ADB forward and use that port in the SSH client. The onn needs its own Wi-Fi
or Ethernet connection for internet access; ADB forwarding does not provide one.

## Direct LAN access

Add `--listen 0.0.0.0` to allow connections through the device's network
interfaces. Connect to its current LAN address using the printed port. Use
`--port` to select another port.

Root SSH provides full administrative control to authenticated clients. Use a
trusted network. Direct LAN operation was not part of the recorded live tests.

## Status, stop, and reboot

```sh
onndemand status --target DEVICE_TARGET
onndemand stop --target DEVICE_TARGET
```

These commands require the temporary-root session to remain available. Stopping
SSH does not undo temporary root. Reboot to end the rooted session.

The server files, authentication settings, and device host key remain under
`/data/local/onn-rootssh`. There is no automatic restart after a reboot. Starting
again reuses the host identity; password modes ask for a password again.

Host-side keys are under `ssh/client/` in the tool's state directory. Installed
state defaults to `~/.local/share/onndemand`; checkout state uses `work/`.
`ONNDEMAND_HOME` overrides that location. These are private files, not support
attachments.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| ADB is unauthorized or offline | Accept the TV prompt and confirm the intended transport with `adb devices -l`. |
| SSH connection is refused | Check server status, listener address, port, and ADB forwarding. |
| Authentication fails | Use the configured method and matching private key; stop before reconfiguring authentication. |
| Host-key fingerprint changes | Verify the device and configuration before accepting the change. |
| A root or PID check refuses to continue | Inspect the reported state; do not bypass the guard. |
| A command times out | It may still be running. Inspect it before retrying or removing locks. |
| Hostnames do not resolve | Confirm that the onn has an active network connection. |
| An Android app-management command fails | Use the normal authorized ADB shell; some framework operations are unavailable in the root shell. |

## Tested scope

Live tests on one `coffey` unit, firmware build 15051976, verified root shell
access, interactive terminals, authentication modes, rejected credentials,
binary stdout, separate stderr, command exit status, and stop/start with a
stable host identity. They reused an existing temporary-root session through
USB ADB forwarding.

The default ARM64 helper was tested on the device. `--arch arm` selects the
bundled ARMv7 SSH helper, which was not part of those live tests. Normal setup
uses verified bundled helpers. `--build-server` explicitly builds the selected
helper from source; `--server-binary PATH` supplies a local override.

See [compatibility](COFFEY.md), [backup and recovery](RESTORE.md), and
[builds and releases](RELEASING.md) for their separate limitations.
