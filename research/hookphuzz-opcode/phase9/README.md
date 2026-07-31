# HookPhuzz opcode research — Phase 9

## Goal

Resolve request placement, generate PHUZZ-compatible fixture configs, and prove
authenticated and generated-config replay.

## Run

```bash
bash research/hookphuzz-opcode/phase9/run.sh
```

Set `HOOKPHUZZ_BUILD_CA_FILE` only for an approved private TLS root. The
certificate remains a BuildKit secret.

## Evidence

Read `results/phase9-validation-summary.json`, then replay, concurrency, and
stability summaries. A PASS requires the current run ID in every artifact.

## Boundary

Phase 9 uses `hookphuzz-phase9-fixture`; it is not real-plugin validation,
fuzzing, scoring, or a vulnerability claim.
