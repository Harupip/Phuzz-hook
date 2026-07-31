# HookPhuzz opcode research — Phase 8

## Goal

Hand UOPZ-discovered WordPress callback roots to the next opcode request.

## Run

```bash
bash research/hookphuzz-opcode/phase8/run.sh
```

## Evidence

Read `results/final-report.md` and its linked registry/artifact evidence.

## Boundary

The handoff is intentionally two-request and atomically file-backed. Closures
are diagnostic only; config generation and replay start in Phase 9.
