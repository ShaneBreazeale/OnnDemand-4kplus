"""Read-only package assets and writable user state live in separate locations."""
import hashlib
import json
import os
from pathlib import Path

ASSETS = Path(__file__).resolve().parent / 'assets'
CHECKOUT = Path(__file__).resolve().parents[2]
IN_CHECKOUT = (CHECKOUT / 'pyproject.toml').is_file() and (CHECKOUT / 'tools').is_dir()
STATE = Path(os.environ.get('ONNDEMAND_HOME') or
             (CHECKOUT / 'work' if IN_CHECKOUT else Path.home() / '.local/share/onndemand')).expanduser().resolve()


def verified_asset(name):
    """Verify a bundled asset against reviewed package pins before use."""
    manifest = json.loads((ASSETS / 'manifest.json').read_text())
    entry = manifest['files'].get(name)
    if entry is None:
        raise ValueError('No bundled asset pin for ' + name)
    path = ASSETS / name
    if path.stat().st_size != entry['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
        raise ValueError('Bundled asset checksum mismatch: ' + name)
    return path


def shell_environment():
    import sys
    return dict(os.environ, ONNDEMAND_ASSET_ROOT=str(ASSETS), ONNDEMAND_PYTHON=sys.executable)
