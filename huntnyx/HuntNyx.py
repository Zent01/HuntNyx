#!/usr/bin/env python3
"""HuntNyx entry point."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from huntnyx.cli import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print("interrupted")
        raise SystemExit(130)
