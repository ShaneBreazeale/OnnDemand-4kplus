"""Console entry point; banner goes to stderr so stdout stays scriptable."""
import argparse
import sys
from . import __version__


def splash(stream=None):
    print(f'\n  OnnDemand  v{__version__}\n  onn. 4K Plus | temporary root + SSH\n', file=stream or sys.stderr)


def main():
    if '--version' in sys.argv[1:]:
        parser = argparse.ArgumentParser(prog='onndemand')
        parser.add_argument('--version', action='version', version=f'OnnDemand {__version__}')
        parser.parse_args()
        return 0
    if sys.stderr.isatty() and '--no-banner' not in sys.argv[1:]:
        splash()
    from .cli import main as cli_main
    return cli_main()
