# HookPhuzz opcode research — Phase 6

## Goal

Prove Phase 5 artifact behavior and request-noise isolation inside WordPress.

## Run

```bash
bash research/hookphuzz-opcode/phase6/run.sh
```

## Evidence

Read `results/final-verdict.txt`; raw enabled/disabled evidence remains available
after failures.

## Boundary

Noise is classified by event order and fixture identity, not callback context.
UOPZ, config generation, and replay are not loaded.
