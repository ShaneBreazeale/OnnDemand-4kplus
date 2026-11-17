#!/usr/bin/env python3
"""Checkout compatibility launcher; installed users run `onndemand`."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from onndemand.entry import main
if __name__ == '__main__':
    sys.exit(main())
