#!/usr/bin/env python3
"""Verify that a clean machine can rebuild Phase 13's local base image."""
from __future__ import annotations
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PHASE11 = ROOT / "research/hookphuzz-opcode/phase11-rest-method-generalization"
PHASE13 = Path(__file__).resolve().parents[1]


def run(command: list[str], timeout: int) -> None:
    subprocess.run(command, cwd=ROOT, check=True, timeout=timeout)


def main() -> int:
    required = [PHASE11 / "Dockerfile", PHASE11 / "scripts/container-entrypoint.sh", PHASE11 / "scripts/phase11-rest.conf", PHASE13 / "Dockerfile", PHASE13 / "docker-compose.yml", PHASE13 / "scripts/run_current_cf7.py"]
    if any(not path.is_file() for path in required):
        raise SystemExit("missing_portability_input")
    run(["docker", "build", "--pull=false", "-t", "hookphuzz-phase11-rest-method:local", "-f", str(PHASE11 / "Dockerfile"), str(PHASE11)], 600)
    run(["docker", "build", "--pull=false", "-t", "hookphuzz-phase13:local", "-f", str(PHASE13 / "Dockerfile"), str(ROOT)], 300)
    print("PHASE13_PORTABILITY_BUILD_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
