# OnnDemand-4kplus

**OnnDemand** provides on-demand temporary root and SSH access for the
**onn. 4K Plus** Android TV device (`coffey`). Use a root shell for customization,
backups, and housekeeping without installing a permanent root boot service.

**Tested device:** onn. 4K Plus, Android 14, firmware build **15051976**
(`URO4.260304.011.B1`). Other devices and firmware versions need separate
validation. A reboot clears temporary root and stops SSH.

## Why this approach?

OnnDemand is intended for maintenance and customization while keeping the
device's original boot configuration in place. The workflow does not unlock
the bootloader, flash replacement boot images, or require a factory reset.

Keeping the stock configuration is a deliberate choice: the aim is to retain
normal device behavior and streaming compatibility while providing
administrative access when you need it. Access is temporary, so a reboot ends
the root session and stops SSH. Files, settings, and app changes you choose to
make can still persist.

Streaming behavior also depends on the firmware, app, and service. Retaining
the stock boot configuration is not a guarantee of playback quality or app
compatibility; check the services you rely on after making changes.

## Features

- Start root SSH through the existing temporary-root command loop.
- Choose SSH key, password, or key OR password authentication.
- Reuse an existing SSH key, or generate and save one on the first setup.
- Use interactive terminals, binary command output, and command exit codes.
- Collect device backups and review reversible app cleanup options.

SSH defaults to device loopback through authorized ADB forwarding. Direct LAN
access is an explicit option. Client private keys stay on your computer, and
the device generates its own persistent SSH host identity.

## Installation

Clone the repository with an account that has access to this private repo:

```sh
git clone https://github.com/ShaneBreazeale/OnnDemand-4kplus.git
cd OnnDemand-4kplus
```

You need:

- uv (which can manage the required Python version), or Python 3.10+ with scrypt support.
- Android platform-tools (`adb`) and an authorized USB or network ADB connection.
- An OpenSSH client; `ssh-keygen` is needed if no client key exists yet.
- Bash on macOS or Linux. Native Windows is not supported by the shell wrappers.

The distribution bundles checksum-verified ARM64/ARMv7 SSH helpers, the coffey
root payload, and its loader. Go and the Android NDK are not required for normal
use. Vendored source, pinned toolchains, and build recipes are included for
maintainers; see [packaging and releases](docs/RELEASING.md).

## Quickstart

Install the CLI from this checkout and inspect the available options:

```sh
uv tool install .
onndemand --version
onndemand --help
adb devices -l
```

For development, use `uv run onndemand`. The existing `python3 onndemand.py`
launcher remains available.

Replace `DEVICE_SERIAL_OR_IP:PORT` below with one authorized ADB transport from
`adb devices`. Start SSH with the default key authentication:

```sh
onndemand --target DEVICE_SERIAL_OR_IP:PORT
```

The tool reuses its saved client key or a standard key pair in `~/.ssh`. If no
key is available, it generates an Ed25519 pair once. Installed state defaults to
`~/.local/share/onndemand`; checkout commands retain `work/`. Use `ONNDEMAND_HOME`
to choose a state directory. It prints the selected identity, device host-key fingerprint,
and connection command. If the temporary-root loop is already running, pass
`--skip-root`. The root launcher prompts before a new root attempt.

The default uses verified bundled helpers. `--build-server` explicitly builds
the SSH helper with Go; `--server-binary PATH` selects your own local build.

On interactive startup, the CLI displays an OnnDemand banner and its packaged
version. Release versions come from Git tags (for example, `v1.2.3` becomes
`1.2.3`). `--no-banner` suppresses the banner, and `--version` works without ADB.

## Authentication and usage

Use a particular public key:

```sh
onndemand --target DEVICE_SERIAL_OR_IP:PORT \
  --public-key ~/.ssh/id_ed25519.pub
```

Enter a password at a hidden prompt:

```sh
onndemand --target DEVICE_SERIAL_OR_IP:PORT --auth password
```

Accept either a key OR a password:

```sh
onndemand --target DEVICE_SERIAL_OR_IP:PORT --auth both
```

Inspect or stop SSH:

```sh
onndemand status --target DEVICE_SERIAL_OR_IP:PORT
onndemand stop --target DEVICE_SERIAL_OR_IP:PORT
```

Stop a running SSH server before reconfiguring its authentication. Passwords
have no command-line argument and no shared default; the device stores a salted
scrypt verifier. `both` means either credential works, rather than requiring two
factors. See [the SSH guide](docs/SSH.md) for forwarding, LAN access, host-key
verification, key storage, and restart behavior.

## Validation and limitations

Live SSH tests on one coffey unit verified root UID 0, interactive PTYs,
authentication modes, rejected credentials, binary stdout, separate stderr,
command status, and stop/start with a stable host key. These tests reused an
existing root loop over USB ADB forwarding. They did not validate a new exploit
attempt, direct LAN access, or every firmware version.

Temporary root reduces runtime security protections until reboot. Stopping SSH
does not end temporary root. Some Android framework commands are unavailable
in the root shell; use the normal authorized ADB shell for those operations. SSH does not provide an internet
connection: the onn still needs Wi-Fi or Ethernet for network access.

This checkout includes code inherited from a separate **2026 onn. 4K Pro
(`jarvis2`)** permanent-root project. Its installer and firmware pins do not
apply to the 4K Plus. The original README is preserved in
[README.upstream.md](README.upstream.md).

## Documentation

See the [documentation index](docs/index.md) for device setup, temporary-root
behavior, SSH, backup limits, and maintainer guides.

## Development and contributing

Run the SSH setup and server tests:

```sh
python3 -m unittest discover -s tests -p test_coffey_ssh.py
cd native/rootssh
go test -race ./...
```

For compatibility reports, include the model, firmware build, helper architecture,
and sanitized error output. Keep private keys, passwords, backups, and private
device reports out of issues and pull requests.

## License

See [THIRD_PARTY.md](THIRD_PARTY.md) for provenance and dependency licenses.
The existing project does not grant an open-source license for its original
workflow and helper sources. Public availability alone does not change that.
