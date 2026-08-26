"""Compatibility re-export for entrypoint classification."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from discovery.entrypoints.classifier import *  # noqa: F401,F403
from discovery.entrypoints.classifier import _classify_callback, _normalize_callback


if __name__ == "__main__":
    raise SystemExit(main())
