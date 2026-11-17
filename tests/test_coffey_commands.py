"""Wrapper regression tests using a filesystem-backed fake device and loader."""
from contextlib import contextmanager, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from tools import temp_root as tr

ROOT = Path(__file__).resolve().parents[1]
FAKE_ADB = r'''
import os, shutil, subprocess, sys
from pathlib import Path
root = os.environ['FAKE_REMOTE']
args = sys.argv[1:]
if args[:1] == ['-s']: args = args[2:]
def translate(s):
    return s.replace('/data/local/tmp/rt', root).replace('/system/bin/sh', '/bin/sh')
if args == ['get-state']:
    print('device'); sys.exit(0)
if args[0] == 'push':
    Path(translate(args[2])).write_bytes(Path(args[1]).read_bytes().replace(
        b'/data/local/tmp/rt', root.encode()).replace(b'/system/bin/sh', b'/bin/sh'))
    sys.exit(0)
if args[0] == 'exec-out':
    result = subprocess.run([translate(a) for a in args[1:]], stderr=subprocess.STDOUT)
    sys.exit(0) # Actual raw ADB does not propagate remote exit status.
if args[0] == 'pull':
    shutil.copyfile(translate(args[1]), args[2]); sys.exit(0)
assert args[0] == 'shell', args
if args[1:2] == ['-T']: args.pop(1)
command = ' '.join(args[1:])
if 'ps -A' in command: sys.exit(0 if os.environ.get('FAKE_LOOP', '1') == '1' else 1)
if command == 'getprop ro.product.device':
    print(os.environ.get('FAKE_DEVICE', 'coffey')); sys.exit(0)
if command == 'getprop ro.build.fingerprint':
    print(os.environ.get('FAKE_FINGERPRINT', 'fake-firmware')); sys.exit(0)
if 'loader.status' in command:
    print('fake loader status'); sys.exit(0)
sys.exit(subprocess.run(['/bin/sh', '-c', translate(command)]).returncode)
'''


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.remote = self.root / 'remote'
        self.remote.mkdir()
        adb = self.root / 'adb'
        adb.write_text('#!' + sys.executable + '\n' + FAKE_ADB)
        adb.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        FAKE_REMOTE=str(self.remote))
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.loader, daemon=True)
        self.worker.start()
        self.addCleanup(self.stop_loader)

    def stop_loader(self):
        self.stop.set()
        self.worker.join(timeout=6)
        self.assertFalse(self.worker.is_alive())

    def loader(self):
        while not self.stop.wait(0.01):
            command = self.remote / 'cmd'
            if command.exists():
                running = self.remote / 'cmd.run'
                command.rename(running)
                with (self.remote / 'out').open('wb') as out:
                    result = subprocess.run(['/bin/sh', str(running)], stdout=out,
                                            stderr=subprocess.STDOUT)
                    out.write(('\n__RC=%s__\n' % result.returncode).encode())
                running.unlink()

    def sudo(self, *args):
        return subprocess.run(['bash', str(ROOT / 'tools/coffey-sudo.sh'), *args],
                              env=self.env, capture_output=True, timeout=12)

    def wait_for(self, path):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if path.exists(): return
            time.sleep(0.01)
        self.fail('timed out waiting for ' + str(path))

    def test_binary_output_and_stderr_are_preserved(self):
        result = self.sudo("printf '\\000\\377data\\n\\n'; printf 'error\\n' >&2; exit 7")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout, b'\x00\xffdata\n\n')
        self.assertEqual(result.stderr, b'error\n')

    def test_printed_status_markers_do_not_end_a_command(self):
        result = self.sudo("printf '__RC=0__\\n'; sleep 0.4; printf 'finished\\n'; exit 9")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertEqual(result.stdout, b'__RC=0__\nfinished\n')

    def test_tar_output_round_trips(self):
        payload = bytes(range(256)) * 100
        (self.remote / 'payload.bin').write_bytes(payload)
        result = self.sudo(f'tar -C {self.remote} -cf - payload.bin')
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            self.assertEqual(archive.extractfile('payload.bin').read(), payload)

    def test_stdin_script_and_empty_stdout(self):
        result = subprocess.run(['bash', str(ROOT / 'tools/coffey-sudo.sh')],
                                env=self.env, input=b'exit 6\n', capture_output=True, timeout=8)
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertEqual(result.stdout, b'')

    def test_concurrent_caller_cannot_overwrite_a_command(self):
        first = subprocess.Popen(['bash', str(ROOT / 'tools/coffey-sudo.sh'),
                                  f'touch {self.remote}/started; sleep 1; printf first'],
                                 env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.wait_for(self.remote / 'started')
            second = self.sudo('printf second')
            self.assertNotEqual(second.returncode, 0)
            self.assertIn(b'another command', second.stderr)
            out, err = first.communicate(timeout=8)
            self.assertEqual(first.returncode, 0, err)
            self.assertEqual(out, b'first')
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate()

    def test_timeout_keeps_lock_until_command_finishes(self):
        result = self.sudo('--timeout', '1', 'sleep 2; printf done')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'may still be running', result.stderr)
        self.assertTrue((self.remote / 'command.lock').is_dir())
        blocked = self.sudo('printf should-not-run')
        self.assertNotEqual(blocked.returncode, 0)
        end = time.monotonic() + 5
        while (self.remote / 'command.lock').exists() and time.monotonic() < end:
            time.sleep(0.02)
        self.assertFalse((self.remote / 'command.lock').exists())
        result = self.sudo('printf recovered')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'recovered')

    def test_invalid_timeouts_are_rejected(self):
        for value in ('0', '-1', 'abc', '1+1'):
            result = self.sudo('--timeout', value, 'id')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'timeout must be', result.stderr)

    def test_force_refuses_live_loop_instead_of_claiming_rerun(self):
        result = subprocess.run(['bash', str(ROOT / 'tools/coffey-root.sh'), '--force', '--yes'],
                                env=self.env, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'refusing a duplicate loop', result.stderr)

    def test_force_cannot_bypass_device_check(self):
        result = subprocess.run(['bash', str(ROOT / 'tools/coffey-root.sh'), '--force', '--yes'],
                                env=dict(self.env, FAKE_DEVICE='other'), capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'not coffey', result.stderr)

    def test_fresh_root_rejects_unsupported_firmware_before_deployment(self):
        result = subprocess.run(['bash', str(ROOT / 'tools/coffey-root.sh'), '--yes'],
                                env=dict(self.env, FAKE_LOOP='0'), capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'firmware differs', result.stderr)

    def test_fresh_root_rejects_a_corrupt_bundled_payload(self):
        assets = self.root / 'assets'
        (assets / 'payload').mkdir(parents=True)
        source = ROOT / 'src/onndemand/assets'
        (assets / 'payload/coffey-root-arm64').write_bytes(b'corrupt')
        (assets / 'payload/rootloop.sh').write_bytes((source / 'payload/rootloop.sh').read_bytes())
        (assets / 'manifest.json').write_bytes((source / 'manifest.json').read_bytes())
        env = dict(self.env, FAKE_LOOP='0', ONNDEMAND_ASSET_ROOT=str(assets),
                   ONNDEMAND_PYTHON=sys.executable,
                   FAKE_FINGERPRINT='onn/coffey/coffey:14/URO4.260304.011.B1/15051976:user/release-keys')
        result = subprocess.run(['bash', str(source / 'scripts/coffey-root.sh'), '--yes'],
                                env=env, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum mismatch', result.stderr)


class HarnessExitTests(unittest.TestCase):
    def test_failed_and_interrupted_exec_return_failure_and_keep_receipt(self):
        for failure in (7, tr.Stop('session lost')):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                class Session:
                    def text(self, *a, **kw):
                        if isinstance(failure, Exception): raise failure
                        return {'text': 'command output', 'returncode': failure}

                @contextmanager
                def opened(*a, **kw):
                    try:
                        yield Session(), {}, {'fingerprint': 'fake'}
                    finally:
                        kw['state']['cleanup_removed'] = True

                output = Path(directory) / 'receipt'
                with patch.object(tr.shutil, 'which', return_value='fake-adb'), \
                     patch.object(tr, 'open_session', opened), redirect_stdout(io.StringIO()):
                    rc = tr.main(['--target', 'fake', '--loader', 'unused', '--loader-sha256',
                                  'unused', '--exec', 'false', '--output-dir', str(output)])
                self.assertEqual(rc, 7 if failure == 7 else 5)
                receipt = json.loads((output / 'session.json').read_text())
                self.assertTrue(receipt['root_obtained'])
                if failure == 7:
                    self.assertEqual(receipt['command']['returncode'], 7)
                else:
                    self.assertEqual(receipt['stop_reason'], 'session lost')


if __name__ == '__main__':
    unittest.main()
