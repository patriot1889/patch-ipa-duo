#!/usr/bin/env python3
"""Build distributable iOS arm64/arm64e dylibs using Xcode on macOS."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ipaduo.native import build_bundles
from ipaduo.errors import Problem

if __name__ == '__main__':
    try:
        build_bundles()
    except (Problem, OSError) as error:
        sys.exit(str(error))
