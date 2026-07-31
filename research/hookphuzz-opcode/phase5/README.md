# HookPhuzz opcode research — Phase 5

## Goal

Write direct superglobal reads as request-local JSON artifacts under Apache.

## Run

```bash
bash research/hookphuzz-opcode/phase5/run.sh
```

## Evidence

Read `results/final-verdict.txt`, then the semantic, concurrency, stability,
event-cap, and sample-event outputs.

## Boundary

`X-Fuzzer-Covid` must be valid and unique. Artifacts contain metadata, never
request values. This phase runs no WordPress, config generation, or replay.
