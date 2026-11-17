#!/usr/bin/env python3
"""OnnDemand: temporary root and SSH for onn. 4K Plus (coffey).

Authentication: key (default), password, or both (key OR password).
No password arguments, shared credentials, boot services, or system account edits.
"""
import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import warnings
from . import __version__
from .runtime import ASSETS, STATE, CHECKOUT, verified_asset, shell_environment

REMOTE = '/data/local/onn-rootssh'


class Stop(Exception):
    pass


def run(argv, **kwargs):
    try:
        result = subprocess.run([str(a) for a in argv], check=False, timeout=kwargs.pop('timeout', 180), **kwargs)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Stop('Command could not complete: ' + str(argv[0])) from error
    if result.returncode:
        raise Stop('Command failed: ' + str(argv[0]))
    return result


def public_keys(paths):
    keys = []
    for path in paths:
        text = path.read_text()
        if 'PRIVATE KEY' in text:
            raise Stop('Supply a public key (.pub), never a private key')
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2 or parts[0] not in ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
                                                  'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'):
                raise Stop('Unsupported public key or authorized_keys options')
            try:
                raw = base64.b64decode(parts[1], validate=True)
                size = struct.unpack('>I', raw[:4])[0]
                if raw[4:4+size].decode() != parts[0]:
                    raise ValueError()
            except (ValueError, UnicodeError, struct.error) as error:
                raise Stop('Malformed public key') from error
            keys.append(' '.join(parts[:2]))
    return keys


def client_key(mode, supplied, home=None, directory=None):
    """Reuse an explicit, saved, or standard user key; generate only once."""
    if supplied or mode == 'password':
        return supplied, None
    home = home or Path.home()
    directory = directory or STATE / 'ssh/client'
    private = directory / 'id_ed25519'
    public = directory / 'id_ed25519.pub'
    if private.is_file() and public.is_file():
        public_keys([public])
        return [public], private
    if private.exists() or public.exists():
        raise Stop('Saved SSH key pair is incomplete; restore it or supply --public-key')
    for name in ('id_ed25519', 'id_ecdsa', 'id_rsa'):
        candidate = home / '.ssh' / name
        candidate_public = candidate.with_name(name + '.pub')
        if candidate.is_file() and candidate_public.is_file():
            public_keys([candidate_public])
            return [candidate_public], candidate
    keygen = shutil.which('ssh-keygen')
    if not keygen:
        raise Stop('Install ssh-keygen or supply --public-key PATH')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = directory / '.generate-lock'
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise Stop('SSH key generation is already in progress; retry when it finishes') from error
    os.close(fd)
    try:
        # Check again under the lock. Never let ssh-keygen overwrite a key.
        if private.exists() or public.exists():
            raise Stop('SSH key files appeared during setup; retry to reuse them')
        with tempfile.TemporaryDirectory(prefix='.new-key-', dir=directory) as temporary:
            generated = Path(temporary) / 'id_ed25519'
            run([keygen, '-q', '-t', 'ed25519', '-N', '', '-C', 'OnnDemand', '-f', generated],
                stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            generated.chmod(0o600)
            os.link(generated, private)
            os.link(generated.with_suffix('.pub'), public)
        return [public], private
    finally:
        lock.unlink()


def hidden_password(message):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            return getpass.getpass(message)
    except (getpass.GetPassWarning, EOFError) as error:
        raise Stop('A terminal with hidden password input is required') from error


def auth_config(mode, paths, prompt=hidden_password):
    if mode not in ('key', 'password', 'both'):
        raise Stop('Authentication must be key, password, or both')
    keys = public_keys(paths)
    if mode in ('key', 'both') and not keys:
        raise Stop('Key authentication requires --public-key PATH (one or more .pub files)')
    if mode == 'password' and keys:
        raise Stop('Use --auth both to enable keys along with a password')
    config = {'auth': mode, 'keys': keys}
    if mode in ('password', 'both'):
        password = prompt('New SSH password: ')
        if not password or len(password.encode()) > 1024:
            raise Stop('Password must contain 1 to 1024 UTF-8 bytes')
        if password != prompt('Confirm SSH password: '):
            raise Stop('Passwords do not match')
        salt = secrets.token_bytes(16)
        config['password_salt'] = salt.hex()
        config['password_hash'] = hashlib.scrypt(password.encode(), salt=salt, n=32768,
                                                 r=8, p=1, dklen=32, maxmem=64 << 20).hex()
    return config


def build_server(arch):
    go = shutil.which('go')
    if not go:
        raise Stop('Install Go 1.26 or later to build the SSH helper, or supply --server-binary')
    output = STATE / 'ssh' / ('rootssh-' + arch)
    output.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
    if arch == 'arm':
        env['GOARM'] = '7'
    source = CHECKOUT / 'native/rootssh'
    if not source.is_dir():
        source = ASSETS / 'ssh-source'
    run([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=', '-o', output, '.'],
        cwd=source, env=env, timeout=600)
    return output


def verify_binary(path, arch):
    with path.open('rb') as stream:
        header = stream.read(20)
    machine = 183 if arch == 'arm64' else 40
    if len(header) < 20 or header[:4] != b'\x7fELF' or header[5] != 1 or struct.unpack('<H', header[18:20])[0] != machine:
        raise Stop('SSH helper is not an ELF binary for the selected ARM architecture')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def root_command(target, script):
    return run(['bash', ASSETS / 'scripts/coffey-sudo.sh', '--serial', target, '--', script],
               capture_output=True, text=True, timeout=180, env=shell_environment()).stdout


def process_check():
    return f'''D={shlex.quote(REMOTE)}
if [ -L "$D" ]; then echo 'SSH directory is a symlink' >&2; exit 1; fi
if [ -e "$D" ]; then
  [ "$(stat -c %u "$D")" = 0 ] && [ "$(stat -c %a "$D")" = 700 ] || {{ echo 'SSH directory must be root-owned and mode 700' >&2; exit 1; }}
fi
pid=''
if [ -f "$D/server.pid" ]; then
  read -r pid < "$D/server.pid"
  case "$pid" in ''|*[!0-9]*) echo 'Invalid SSH PID file' >&2; exit 1;; esac
  if [ -d "/proc/$pid" ]; then
    [ "$(readlink /proc/$pid/exe)" = "$D/rootssh" ] || {{ echo 'PID does not identify this SSH server' >&2; exit 1; }}
  else pid=''; fi
fi
'''


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--version', action='version', version='OnnDemand ' + __version__)
    p.add_argument('--no-banner', action='store_true', help='Suppress the interactive startup banner')
    p.add_argument('action', choices=('start', 'stop', 'status'), nargs='?', default='start')
    p.add_argument('--target', required=True, help='Authorized ADB serial or IP:port')
    p.add_argument('--auth', choices=('key', 'password', 'both'), default='key',
                   help='both accepts a key OR a password; default: key')
    p.add_argument('--public-key', type=Path, action='append', default=[],
                   help='Use these .pub files; otherwise reuse an existing key or generate one once')
    p.add_argument('--listen', type=ipaddress.IPv4Address, default=ipaddress.IPv4Address('127.0.0.1'))
    p.add_argument('--port', type=int, default=2222)
    p.add_argument('--arch', choices=('arm64', 'arm'), default='arm64')
    server = p.add_mutually_exclusive_group()
    server.add_argument('--server-binary', type=Path, help='Explicit local SSH helper instead of the verified bundled helper')
    server.add_argument('--build-server', action='store_true', help='Build the SSH helper from source with Go')
    p.add_argument('--skip-root', action='store_true', help='Use an already running temporary-root loop')
    p.add_argument('--yes', action='store_true', help='Pass --yes to the temporary-root launcher')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not 1 <= args.port <= 65535:
            raise Stop('Port must be between 1 and 65535')
        if not shutil.which('adb'):
            raise Stop('ADB was not found')
        # Build and collect credentials before touching the device.
        if args.action == 'start':
            binary = args.server_binary or (build_server(args.arch) if args.build_server else
                                             verified_asset('ssh/rootssh-' + args.arch))
            digest = verify_binary(binary, args.arch)
            keys, identity_file = client_key(args.auth, args.public_key)
            config = auth_config(args.auth, keys)
        identity = run(['adb', '-s', args.target, 'shell', 'getprop ro.product.device'],
                       capture_output=True, text=True).stdout.strip()
        if identity != 'coffey':
            raise Stop('Selected device is not coffey')
        if args.action == 'start' and not args.skip_root:
            verified_asset('payload/coffey-root-arm64')
            verified_asset('payload/rootloop.sh')
            command = ['bash', ASSETS / 'scripts/coffey-root.sh', '--serial', args.target]
            if args.yes: command.append('--yes')
            run(command, timeout=600, env=shell_environment())
        if root_command(args.target, 'id -u').strip() != '0':
            raise Stop('The temporary-root loop did not prove uid 0')
        check = process_check()
        if args.action == 'status':
            print(root_command(args.target, check + '\n[ -n "$pid" ] && echo "SSH running pid=$pid" || echo "SSH stopped"'), end='')
            return 0
        if args.action == 'stop':
            print(root_command(args.target, check + '\nif [ -n "$pid" ]; then kill "$pid" || exit 1; fi\necho "SSH stop requested"'), end='')
            return 0
        root_command(args.target, check + '\n[ -z "$pid" ] || { echo "SSH is already running; stop it before reconfiguring" >&2; exit 1; }')
        stage = '/data/local/tmp/onn-ssh-' + secrets.token_hex(8)
        run(['adb', '-s', args.target, 'shell', 'mkdir -m 700 ' + stage])
        try:
            with tempfile.TemporaryDirectory(prefix='onn-ssh-') as directory:
                config_path = Path(directory) / 'auth.json'
                config_path.write_text(json.dumps(config))
                config_path.chmod(0o600)
                run(['adb', '-s', args.target, 'push', binary, stage + '/rootssh'], stdout=subprocess.DEVNULL)
                run(['adb', '-s', args.target, 'push', config_path, stage + '/auth.json'], stdout=subprocess.DEVNULL)
            script = check + f'''
[ -z "$pid" ] || exit 1
umask 077
mkdir -p "$D" || exit 1
chown 0:0 "$D" && chmod 700 "$D" || exit 1
[ "$(sha256sum {stage}/rootssh | cut -d ' ' -f 1)" = '{digest}' ] || exit 1
cp {stage}/rootssh "$D/rootssh.new" && chmod 700 "$D/rootssh.new" || exit 1
cp {stage}/auth.json "$D/auth.json.new" && chmod 600 "$D/auth.json.new" || exit 1
"$D/rootssh.new" --check-config --config "$D/auth.json.new" || exit 1
mv "$D/rootssh.new" "$D/rootssh" && mv "$D/auth.json.new" "$D/auth.json" || exit 1
rm -f "$D/server.pid"
nohup "$D/rootssh" --config "$D/auth.json" --host-key "$D/host_key" --pid-file "$D/server.pid" --listen '{args.listen}:{args.port}' </dev/null >"$D/server.log" 2>&1 &
sleep 1
[ -s "$D/server.pid" ] || {{ cat "$D/server.log" >&2; exit 1; }}
read -r pid < "$D/server.pid"
kill -0 "$pid" || exit 1
cat "$D/server.log"
'''
            print(root_command(args.target, script), end='')
        finally:
            run(['adb', '-s', args.target, 'shell', 'rm -rf ' + shlex.quote(stage)], stdout=subprocess.DEVNULL)
        print('SSH authentication: ' + args.auth + (' (key OR password)' if args.auth == 'both' else ''))
        identity_options = ''
        if identity_file:
            print('Reusing client key: ' + str(identity_file))
            identity_options = ' -o IdentitiesOnly=yes -i ' + shlex.quote(str(identity_file))
        if args.listen.is_loopback:
            print(f'Connect through ADB: adb -s {shlex.quote(args.target)} forward tcp:{args.port} tcp:{args.port}')
            print(f'Then: ssh{identity_options} -p {args.port} root@127.0.0.1')
        else:
            print(f'Connect: ssh{identity_options} -p {args.port} root@DEVICE_IP')
        print('Check the displayed host-key fingerprint when connecting. Reboot clears root and stops SSH.')
        return 0
    except (Stop, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
