# HookPhuzz opcode research — Phase 7

## Goal

Attribute direct reads to configured WordPress callback roots and their helpers.

## Run

```bash
bash research/hookphuzz-opcode/phase7/run.sh
```

## Evidence

Read `results/final-report.md`, linked JSON, and `sample-artifacts/`.

## Boundary

Roots come from `hookphuzz_opcode.target_callbacks`. Closure labels are
diagnostic; callback discovery, config generation, and replay are excluded.
