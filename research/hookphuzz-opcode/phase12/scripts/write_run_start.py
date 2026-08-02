#!/usr/bin/env python3
"""Persist the Phase 12 current-run boundary before any artifacts exist."""
from __future__ import annotations

import json
import sys
from pathlib import Path


results, run_id, started_epoch, compose_project = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
target = results / "run-start.json"
temporary = target.with_suffix(".tmp")
temporary.write_text(json.dumps({"schema_version": 1, "run_id": run_id, "started_epoch": started_epoch, "cf7_compose_project": compose_project}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.replace(target)
