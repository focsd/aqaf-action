#!/usr/bin/env python3
"""Compatibility entrypoint; install package for the `aqaf` command."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aqaf.cli import main
if __name__ == '__main__':
    sys.exit(main())
