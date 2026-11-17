#!/usr/bin/env python3
"""Windows/macOS entry point; run with Python 3.10 or newer."""
import sys

if sys.version_info < (3, 10):
    sys.exit("Python 3.10 or newer is required.")

from ipaduo.cli import main

if __name__ == "__main__":
    sys.exit(main())
