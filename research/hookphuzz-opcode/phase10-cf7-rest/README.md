# Phase 10 CF7 REST

## Goal

Discover Contact Form 7 5.7.7 REST parameters and replay the generated config.

## Run

```bash
bash research/hookphuzz-opcode/phase10-cf7-rest/run.sh
```

Use `HOOKPHUZZ_BUILD_CA_FILE` only for an approved private TLS root.

## Evidence

The retained result is `PHASE_10_CF7_REST_FAIL`; authentication blocked
callback/runtime proof. Read `results/final-report.md` and `run.stdout.log`.

## Boundary

PASS requires registration, callback reachability, runtime
`WP_REST_Request::get_param`, config generation, and replay. The copied Phase 9
extension is intentional: this lab must remain independent of other phase code.
