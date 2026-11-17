#!/usr/bin/env python3
"""Rebuild pinned native assets, or check their binary and source checksums offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'src/onndemand/assets'
GO_VERSION = 'go1.27.4'
NDK_VERSION = '28.2.13676358'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = list((ROOT / 'vendor/coffey').rglob('*'))
    paths += list((ROOT / 'native/rootssh').rglob('*'))
    paths += [ASSETS / 'payload/rootloop.sh', Path(__file__).resolve()]
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(paths) if p.is_file()
            and p.suffix not in ('.pyc',) and '__pycache__' not in p.parts}


def check():
    manifest = json.loads((ASSETS / 'manifest.json').read_text())
    if manifest['sources'] != sources():
        raise SystemExit('Native sources or recipe changed; rebuild and review the manifest')
    expected = {'payload/coffey-root-arm64', 'payload/rootloop.sh', 'ssh/rootssh-arm64', 'ssh/rootssh-arm'}
    if set(manifest['files']) != expected:
        raise SystemExit('Asset manifest is incomplete')
    for name, pin in manifest['files'].items():
        path = ASSETS / name
        if path.stat().st_size != pin['bytes'] or sha(path) != pin['sha256']:
            raise SystemExit('Asset checksum mismatch: ' + name)
    print('All bundled native assets and source pins verified')


def build(ndk, go):
    properties = (ndk / 'source.properties').read_text()
    if not any(line.strip() == 'Pkg.Revision = ' + NDK_VERSION for line in properties.splitlines()):
        raise SystemExit('Use Android NDK ' + NDK_VERSION)
    version = subprocess.check_output([go, 'version'], text=True).split()
    if version[2] != GO_VERSION:
        raise SystemExit('Use Go ' + GO_VERSION + ' for release assets')
    host = {'Darwin': 'darwin-x86_64', 'Linux': 'linux-x86_64'}[platform.system()]
    cc = ndk / 'toolchains/llvm/prebuilt' / host / 'bin/aarch64-linux-android34-clang'
    with tempfile.TemporaryDirectory(prefix='onndemand-assets-') as temporary:
        temporary = Path(temporary)
        payload = temporary / 'coffey-root-arm64'
        subprocess.run([str(cc.resolve()), '-O2', '-g0', '-Wall', '-Wextra', '-Isrc',
                        '-DTARGET_CONFIG_H="targets/coffey/target.h"', '-DUSE_PSELECT',
                        'src/launcher.c', 'src/main.c', 'src/util.c', 'src/slide.c', 'src/sysctl.c',
                        '-o', str(payload), '-static', '-pthread'], cwd=ROOT / 'vendor/coffey', check=True)
        outputs = {'payload/coffey-root-arm64': payload}
        for arch in ('arm64', 'arm'):
            binary = temporary / ('rootssh-' + arch)
            env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0', GOARM='7')
            subprocess.run([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
                            '-ldflags=-s -w -buildid=', '-o', str(binary), '.'],
                           cwd=ROOT / 'native/rootssh', env=env, check=True)
            outputs['ssh/rootssh-' + arch] = binary
        for name, binary in outputs.items():
            destination = ASSETS / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(binary.read_bytes())
            destination.chmod(0o755)
    files = {name: {'bytes': (ASSETS / name).stat().st_size, 'sha256': sha(ASSETS / name)}
             for name in (*outputs, 'payload/rootloop.sh')}
    manifest = {'schema': 1, 'toolchains': {'go': GO_VERSION, 'android_ndk': NDK_VERSION},
                'upstream_payload_revision': '33541d1a852a926f782602aa34d79cfbffbd4bb6',
                'device': 'coffey', 'firmware_incremental': '15051976',
                'sources': sources(), 'files': files}
    (ASSETS / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    check()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--ndk', type=Path)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    if args.check:
        check()
    else:
        if not args.ndk:
            parser.error('--ndk PATH is required to rebuild the root payload')
        build(args.ndk, args.go)
