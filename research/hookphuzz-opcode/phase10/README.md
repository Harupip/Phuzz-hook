# HookPhuzz opcode research — Phase 10

## Goal

Package the fixture runtime offline and validate Phase 9 artifact merge,
deduplication, PHUZZ export compatibility, and replay contracts.

## Run

```bash
bash research/hookphuzz-opcode/phase10/run.sh
bash research/hookphuzz-opcode/phase10/scripts/build_offline_image.sh
```

The image build requires all assets locally, uses `--network=none`, and fails
closed when an image or bundled asset is missing.

## Evidence

Packaging evidence and live evidence are separate. Read
`results/phase10-validation-summary.json` and `final-verdict.txt` for the live
verdict; image preflight reports prove packaging only.

## Boundary

The retained live result is `PHASE_10_FAIL` because real-plugin merge, noise,
config, and replay gates are incomplete. CRM and CF7 remain isolated labs.
Phase 10 never redefines the PHUZZ schema or makes fuzzing/vulnerability claims.
