# HookPhuzz opcode research — Phase 0

## Goal

Record PHP 8.2 request-array opcodes and missing-key semantics before building an extension.

## Run

```bash
bash research/hookphuzz-opcode/phase0/run.sh
```

## Evidence

Read `results/raw-opcodes.txt`, `runtime-semantics.txt`, and `environment.txt`.

## Boundary

VLD may fall back to OPcache diagnostics. This phase loads no HookPhuzz
extension, UOPZ, or WordPress.
