"""Compatibility re-export for the WordPress bootstrap probe runner."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery.wordpress.bootstrap_probe_runner import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
