"""Packaging regressions: tagged versions, noninteractive output and asset pins."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from onndemand import __version__, entry, runtime


class DistributionTests(unittest.TestCase):
    def test_version_needs_no_adb_or_device(self):
        with patch.object(sys, 'argv', ['onndemand', '--version']), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as stopped:
                entry.main()
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), 'OnnDemand ' + __version__)

    def test_banner_contains_packaged_version_and_stays_off_stdout(self):
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            entry.splash(stderr)
        self.assertIn('OnnDemand  v' + __version__, stderr.getvalue())
        self.assertIn('onn. 4K Plus', stderr.getvalue())
        self.assertEqual(stdout.getvalue(), '')

    def test_every_bundled_asset_is_verified(self):
        pins = json.loads((runtime.ASSETS / 'manifest.json').read_text())
        for name in pins['files']:
            self.assertTrue(runtime.verified_asset(name).is_file())

    def test_tampered_or_unpinned_assets_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'payload').write_bytes(b'changed')
            (base / 'manifest.json').write_text(json.dumps({'files': {'payload': {'bytes': 1, 'sha256': '0'*64}}}))
            with patch.object(runtime, 'ASSETS', base):
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    runtime.verified_asset('payload')
                with self.assertRaisesRegex(ValueError, 'No bundled asset pin'):
                    runtime.verified_asset('unknown')

    def test_help_does_not_print_a_startup_banner_when_redirected(self):
        result = subprocess.run([sys.executable, str(ROOT / 'onndemand.py'), '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--no-banner', result.stdout)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
