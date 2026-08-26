"""Compatibility CLI for seed-to-config export."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cli.seed_to_config import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
