# HookPhuzz opcode research — Phase 1

## Goal

Prove `ZEND_FETCH_DIM_R` user-handler registration, counting, and safe dispatch.

## Run

```bash
bash research/hookphuzz-opcode/phase1/run.sh
```

## Evidence

Read `results/phase1-summary.md`.

## Boundary

Counts prove handler invocation only. No operand or HTTP provenance is read.
