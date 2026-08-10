from __future__ import annotations

from huntnyx.cli import main

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print("interrupted")
        raise SystemExit(130)
