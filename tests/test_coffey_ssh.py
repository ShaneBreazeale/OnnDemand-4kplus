"""Authentication preparation and deployment guards without device access."""
from contextlib import redirect_stdout
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from onndemand import cli as ssh


def public_key():
    algorithm = b'ssh-ed25519'
    blob = struct.pack('>I', len(algorithm)) + algorithm + struct.pack('>I', 32) + bytes(range(32))
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode()


class SSHTests(unittest.TestCase):
    @unittest.skipUnless(ssh.shutil.which('ssh-keygen'), 'ssh-keygen required')
    def test_generate_once_then_reuse_the_same_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'saved'
            keys, private = ssh.client_key('key', [], home=root / 'home', directory=directory)
            original = private.read_bytes()
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertTrue(ssh.public_keys(keys)[0].startswith('ssh-ed25519 '))
            with patch.object(ssh, 'run', side_effect=AssertionError('must not generate again')):
                again, same = ssh.client_key('both', [], home=root / 'home', directory=directory)
            self.assertEqual((again, same), (keys, private))
            self.assertEqual(private.read_bytes(), original)

    def test_existing_user_key_is_selected_without_copying_private_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'home'
            (home / '.ssh').mkdir(parents=True)
            private = home / '.ssh/id_ed25519'
            private.write_text('existing private key, never uploaded')
            public = private.with_suffix('.pub')
            public.write_text(public_key())
            with patch.object(ssh, 'run', side_effect=AssertionError('must not generate')):
                keys, selected = ssh.client_key('key', [], home=home, directory=root / 'saved')
            self.assertEqual((keys, selected), ([public], private))
            self.assertFalse((root / 'saved').exists())

    def test_explicit_and_password_modes_do_not_select_or_generate_keys(self):
        with patch.object(ssh, 'run', side_effect=AssertionError('must not generate')):
            paths = [Path('/supplied.pub')]
            self.assertEqual(ssh.client_key('key', paths), (paths, None))
            self.assertEqual(ssh.client_key('password', []), ([], None))

    def test_incomplete_saved_key_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            private = directory / 'id_ed25519'
            private.write_text('preserve this')
            with self.assertRaisesRegex(ssh.Stop, 'incomplete'):
                ssh.client_key('key', [], home=directory / 'home', directory=directory)
            self.assertEqual(private.read_text(), 'preserve this')

    def test_each_mode_requires_exact_credentials_and_never_serializes_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key.pub'
            path.write_text(public_key() + ' example\n')
            for mode in ('key', 'password', 'both'):
                config = ssh.auth_config(mode, [] if mode == 'password' else [path], prompt=lambda _: 'test-password')
                self.assertNotIn('test-password', json.dumps(config))
                if mode == 'key':
                    self.assertNotIn('password_hash', config)
                else:
                    derived = hashlib.scrypt(b'test-password', salt=bytes.fromhex(config['password_salt']),
                                             n=32768, r=8, p=1, dklen=32, maxmem=64 << 20)
                    self.assertEqual(derived.hex(), config['password_hash'])
                self.assertEqual(bool(config['keys']), mode != 'password')
            with self.assertRaises(ssh.Stop):
                ssh.auth_config('key', [])
            with self.assertRaises(ssh.Stop):
                ssh.auth_config('password', [path])
            with self.assertRaises(ssh.Stop):
                ssh.auth_config('none', [])

    def test_empty_mismatched_and_private_credentials_are_rejected(self):
        for password in ('', 'a' * 1025):
            with self.assertRaises(ssh.Stop):
                ssh.auth_config('password', [], prompt=lambda _: password)
        replies = iter(('first', 'second'))
        with self.assertRaises(ssh.Stop):
            ssh.auth_config('password', [], prompt=lambda _: next(replies))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private'
            path.write_text('-----BEGIN OPENSSH PRIVATE KEY-----')
            with self.assertRaisesRegex(ssh.Stop, 'never a private key'):
                ssh.public_keys([path])

    def test_setup_keeps_credentials_out_of_commands_and_checks_uid_before_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'rootssh'
            binary.write_bytes(b'\x7fELF' + bytes((2, 1)) + bytes(12) + struct.pack('<H', 183))
            key = Path(directory) / 'key.pub'
            key.write_text(public_key())
            commands, scripts = [], []

            def fake_run(argv, **kwargs):
                commands.append([str(a) for a in argv])
                if 'push' in argv and str(argv[-1]).endswith('/auth.json'):
                    self.assertEqual(json.loads(Path(argv[-2]).read_text())['auth'], 'key')
                return subprocess.CompletedProcess(argv, 0, stdout='coffey\n')

            def fake_root(target, script):
                scripts.append(script)
                return '0\n' if script == 'id -u' else ''

            with patch.object(ssh.shutil, 'which', return_value='fake'), \
                 patch.object(ssh, 'run', side_effect=fake_run), \
                 patch.object(ssh, 'root_command', side_effect=fake_root), redirect_stdout(io.StringIO()):
                code = ssh.main(['--target', 'device', '--skip-root', '--server-binary', str(binary),
                                 '--public-key', str(key)])
            self.assertEqual(code, 0)
            self.assertEqual(scripts[0], 'id -u')
            self.assertNotIn(public_key(), json.dumps(commands) + '\n'.join(scripts))
            self.assertIn('127.0.0.1:2222', scripts[-1])
            self.assertIn('--check-config', scripts[-1])
            for script in scripts:
                result = subprocess.run(['/bin/sh', '-n'], input=script, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_non_root_status_does_not_inspect_or_modify_ssh_files(self):
        with patch.object(ssh.shutil, 'which', return_value='fake'), \
             patch.object(ssh, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='coffey\n')), \
             patch.object(ssh, 'root_command', return_value='2000\n') as root:
            self.assertEqual(ssh.main(['status', '--target', 'device']), 2)
            root.assert_called_once_with('device', 'id -u')

    def test_default_setup_uses_bundled_helper_without_go(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'key.pub'
            key.write_text(public_key())
            with patch.object(ssh.shutil, 'which', return_value='fake-adb'), \
                 patch.object(ssh, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='coffey\n')), \
                 patch.object(ssh, 'root_command', side_effect=lambda target, command: '0\n' if command == 'id -u' else ''), \
                 patch.object(ssh, 'build_server', side_effect=AssertionError('Go must not run')), \
                 patch.object(ssh, 'verified_asset', wraps=ssh.verified_asset) as verify, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(ssh.main(['--target', 'device', '--skip-root', '--public-key', str(key)]), 0)
            verify.assert_called_once_with('ssh/rootssh-arm64')


if __name__ == '__main__':
    unittest.main()
