# OnnDemand — SSH for onn. 4K Plus

`onndemand.py` starts a root SSH shell through the existing coffey
command loop. It supports interactive terminals and remote shell commands.
It does not implement SFTP or port forwarding, install a boot service, modify
Android accounts, or change SELinux. Android framework commands have the same
limitations as the temporary-root loop.

**Status:** Live validation on an onn 4K Plus (`coffey`, build 15051976) on
2026-11-17 passed with the ARM64 helper: SSH sessions reported `uid=0(root)`
in `u:r:kernel:s0`; interactive PTYs, binary stdout, separate stderr, and command
exit codes worked. Key-only, password-only, and key OR password modes accepted
the intended credentials and rejected wrong passwords or disabled methods.
Stop/start preserved the device's host-key fingerprint. These tests reused an
existing root loop and used device loopback through USB ADB forwarding; a fresh
root exploit, direct LAN access, and the ARMv7 helper were not tested here.
Both ARM and ARM64 helpers cross-compile successfully. The package now includes
verified prebuilt helpers, a root payload rebuilt identically from vendored
sources, and the root loader. Fresh installations do not depend on ignored local
exploit artifacts. See [packaging and releases](RELEASING.md).

## Choose authentication

| Mode | Accepted credentials |
| --- | --- |
| `--auth key` (default) | A reused or generated SSH key, or your supplied public key(s) |
| `--auth password` | A password you enter at a hidden prompt |
| `--auth both` | Either your selected SSH key OR your password |

`both` does not require two authentication factors. Empty passwords and
unauthenticated access are refused. There is no shared/default password and
there are no password command-line arguments. The tool confirms your password
and stores only a randomly salted scrypt verifier (N=32768, r=8, p=1).

Client keys are reused, not regenerated for each connection. Checkout state is
under `work/`; installed state defaults to `~/.local/share/onndemand`. Override
either with `ONNDEMAND_HOME`. Selection order:

1. Explicit `--public-key` files.
2. The saved key at `ssh/client/id_ed25519` within the tool's state directory.
3. An existing key pair in `~/.ssh`: `id_ed25519`, `id_ecdsa`, then `id_rsa`.
4. Generate an Ed25519 pair once in that state directory and reuse it afterward.

Automatic discovery requires both the public and private file to exist. The
tool reads only the public key; the private key stays on your computer. If you
use an agent-only key, select its public file explicitly. Generated private keys
have no passphrase, are mode 600 inside a mode 700 directory, and stay in ignored
state storage. For a passphrase-protected or separately managed key, supply its public
file. Do not delete the saved key while you still need to connect to a server
configured with it. Password-only mode does not select or generate a key.

Public keys can also be supplied with `--public-key`; repeat it for multiple files.
Supply `.pub` files, not private keys. Keys with authorized_keys restrictions
are rejected rather than silently losing their restrictions.

## Start and connect

You need Python 3 with scrypt support, authorized ADB, Bash, and an OpenSSH
client. Automatic first-time key generation also needs `ssh-keygen`. Go is not
needed for normal setup: verified ARM64 and ARMv7 SSH helpers are bundled.
`--build-server` explicitly builds from source instead. Go dependencies are
pinned in `native/rootssh/go.mod` and `go.sum`.
The helper is built without libc for Linux ARM64 (the coffey kernel supports
AArch64). `--arch arm` builds a 32-bit ARMv7 helper instead. To use an existing
locally built helper, pass `--server-binary PATH` with the matching `--arch`.
Bundled helpers are checked against package SHA256 pins before upload.
The helper is separate from the existing kernel exploit binary.

The following examples use `192.168.1.50:5555` as an example authorized ADB
transport; replace it with your device's serial or address.

```sh
# Key-only (default): reuse a key, or generate one once
python3 onndemand.py --target 192.168.1.50:5555

# Choose a particular public key instead
python3 onndemand.py --target 192.168.1.50:5555 --public-key ~/.ssh/id_ed25519.pub

# Password-only: prompts twice without echoing the password
python3 onndemand.py --target 192.168.1.50:5555 --auth password

# Accept either your key or your password
python3 onndemand.py --target 192.168.1.50:5555 \
  --auth both --public-key ~/.ssh/id_ed25519.pub
```

Each start first runs `coffey-root.sh` unless `--skip-root` is supplied. The
existing launcher prompts before a new root attempt; `--yes` forwards its
noninteractive confirmation. Existing temporary root can be reused. A live
SSH server is not automatically restarted or reconfigured: stop it first.

By default the server listens only on device loopback, port 2222. Forward it
through your authorized ADB connection:

```sh
adb -s 192.168.1.50:5555 forward tcp:2222 tcp:2222
# Use the SSH command printed by the tool, including its selected identity:
ssh -i work/ssh/client/id_ed25519 -p 2222 root@127.0.0.1
```

For direct access on your LAN, add `--listen 0.0.0.0` when starting the server,
then connect with `ssh -p 2222 root@192.168.1.50`. You can choose another port
with `--port`. Root SSH exposes full control of the device to authenticated
clients; use a trusted network.

The server generates a unique Ed25519 host key on the device and prints its
SHA256 fingerprint. Compare that fingerprint with your SSH client's first
connection prompt. Do not disable host-key verification.

## Stop, inspect, and restart

```sh
python3 onndemand.py status --target 192.168.1.50:5555
python3 onndemand.py stop --target 192.168.1.50:5555
```

These commands use the root loop, so they require it to be alive. Stop checks
that the PID belongs to this helper before sending a termination signal.

A reboot clears temporary root and stops SSH. The server binary, authentication
configuration, and host identity remain under `/data/local/onn-rootssh`, owned
by root in a directory with mode 700. There is no automatic restart. Run start
again to regain temporary root and configure authentication; password modes ask
for the password again. The host key is reused, so restarting preserves the
device's SSH identity. A stale PID from a reboot is discarded only after it is
shown not to refer to a running process; a PID reused by another process stops
installation for inspection.

## Validation

```sh
python3 -m unittest discover -s tests -p test_coffey_ssh.py
cd native/rootssh
go test ./...
```

Go tests exercise real local SSH handshakes for all authentication modes,
rejected credentials, command exit status, binary output, PTYs, and stable host
identity. Python tests cover credential preparation and deployment guards.
