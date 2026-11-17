#!/usr/bin/env python3
"""Check wheel contents, bundled helper hashes, and release version metadata."""
import argparse
import email
import hashlib
import json
from pathlib import Path
import re
import zipfile


def check(path, expected=None):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith('.dist-info/METADATA'))
        metadata = email.message_from_bytes(archive.read(metadata_name))
        if expected and metadata['Version'] != expected:
            raise ValueError('Wheel version does not match release tag')
        manifest = json.loads(archive.read('onndemand/assets/manifest.json'))
        for name, pin in manifest['files'].items():
            data = archive.read('onndemand/assets/' + name)
            if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256']:
                raise ValueError('Bundled binary pin mismatch: ' + name)
        for required in ('onndemand/cli.py', 'onndemand/entry.py', 'onndemand/_version.py',
                         'onndemand/assets/scripts/coffey-root.sh',
                         'onndemand/assets/scripts/coffey-sudo.sh',
                         'onndemand/assets/ssh-source/go.mod',
                         'onndemand/assets/licenses/coffey-APACHE-2.0'):
            if required not in names:
                raise ValueError('Missing package file: ' + required)
        for name in names:
            if '/work/' in name or 'id_ed25519' in name or 'auth.json' in name or 'known_hosts' in name:
                raise ValueError('Private/generated state included in package: ' + name)
        # Host orchestration is pure Python; ARM binaries are data, never loaded
        # into the host process. A universal wheel is deliberate.
        entry = next(name for name in names if name.endswith('.dist-info/entry_points.txt'))
        if 'onndemand = onndemand.entry:main' not in archive.read(entry).decode():
            raise ValueError('CLI entry point is missing')
        print('Verified wheel version ' + metadata['Version'] + ': bundled assets, entry point, and state exclusions')
        return metadata['Version']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    parser.add_argument('--tag', help='Require exact version corresponding to vX.Y.Z (or prerelease)')
    args = parser.parse_args()
    expected = None
    if args.tag:
        if not re.fullmatch(r'v\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?', args.tag):
            parser.error('Tag must be vX.Y.Z or a Python-style prerelease such as v1.2.3rc1')
        expected = args.tag[1:]
    check(args.wheel, expected)
