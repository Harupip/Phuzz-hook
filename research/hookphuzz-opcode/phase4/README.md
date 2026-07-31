# HookPhuzz opcode research — Phase 4

## Goal

Add direct silent-read contexts (`silent_read`, `isset`, and `empty`) to Phase 3.

## Run

```bash
bash research/hookphuzz-opcode/phase4/run.sh
```

## Evidence

Read `results/phase4-summary.md` and compare extension-on/off semantics.

## Boundary

This remains direct opcode-slot provenance. It does not implement value
transport, aliases, helper propagation, WordPress, config generation, or replay.
