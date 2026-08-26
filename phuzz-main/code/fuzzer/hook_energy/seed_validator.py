"""Compatibility CLI and re-export for seed verification."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seed_generation.verification.seed_validator import *  # noqa: F401,F403


if __name__ == "__main__":
    raise SystemExit(main())
