# HookPhuzz opcode research — Phase 3

## Goal

Track direct `GET`, `POST`, `REQUEST`, and `COOKIE` opcode-slot provenance.

## Run

```bash
bash research/hookphuzz-opcode/phase3/run.sh
```

## Evidence

Read `results/phase3-summary.md` and its event samples.

## Boundary

Nested paths are direct opcode provenance, not general dataflow. Values and
zval pointers are never retained; event storage is capped at 4096.
