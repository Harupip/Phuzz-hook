# HookPhuzz Long-Run Benchmark Protocol

## Goal

Measure HookPhuzz without mixing up two separate effects:

- algorithm effect: hook-aware scheduling versus original PHUZZ scheduling
- instrumentation cost: UOPZ hook tracing overhead

Do not use a 20 minute run as final evidence. Treat it as startup/discovery
only. Use 4-6 hour pilot runs first, then 12-24 hour runs for final campaign
data.

## Implementation Notes

The benchmark implementation now supports this protocol directly:

- `benchmark-wordpress-phuzz.ps1` no longer edits `fuzzer/scoring.env` during a
  run. It injects per-mode settings through a generated Compose override.
- The runner accepts comma-separated selections such as
  `-Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE`.
- `PHUZZ_RAW`, `PHUZZ_TRACE`, `HOOK_TRACE`, and `HOOK_FAST` are first-class
  runner modes.
- `RunHours`, `BucketMinutes`, `TraceMinutes`, and `FastSeedLimit` are exposed
  as runner parameters.
- The fuzzer accepts `FUZZER_CONFIG_FILE` so generated configs can live under
  `fuzzer/output/...` instead of being written into `fuzzer/configs`.
- The fuzzer accepts `seed_requests[]` for multi-seed runs and writes
  `fuzzer-output/request-events.jsonl`, which lets `PHUZZ_RAW` report EPS even
  when UOPZ is disabled.
- Hook seed export can generate `hook-fast-config.json` from unauthenticated
  direct seeds. Authenticated seeds are left in warnings/manual review for v1.
- Benchmark summaries include `requests_per_second`, `requests_per_minute`,
  `hook_signal_request_ratio`, `uopz_overhead_ratio`,
  `unique_vulns_found_within_budget`, and the legacy
  `unique_vulns_found_after_30min` alias.
- Each run writes `coverage_timeline.csv`, `coverage_timeline.json`, and
  `run_manifest.json`.

Smoke verification on `photo-gallery` with 10 minutes per mode completed at:

```text
fuzzer/output/benchmarks/20260519-150344-photo-gallery
```

That run confirmed `PHUZZ_RAW`, `PHUZZ_TRACE`, and `HOOK_TRACE` produce request
events, timelines, manifests, and aggregate benchmark results. `PHUZZ_RAW`
correctly has no `total_coverage.json` because UOPZ is disabled.

## Modes

Use these modes in the benchmark runner:

- `PHUZZ_RAW`: original PHUZZ, `PHUZZ_SCORING_MODE=1`, `FUZZER_ENABLE_UOPZ=0`.
- `PHUZZ_TRACE`: original PHUZZ with UOPZ on, useful for coverage curves and overhead comparison.
- `HOOK_TRACE`: hook-aware scoring with UOPZ on for the whole run.
- `HOOK_FAST`: UOPZ on only for `-TraceMinutes`, seed export from `total_coverage.json`, then UOPZ off with generated `FUZZER_CONFIG_FILE`.

Read `PHUZZ_RAW` as the brute-force speed baseline. Read `PHUZZ_TRACE` versus
`HOOK_TRACE` as algorithm comparison under the same tracing cost. Read
`HOOK_FAST` as the practical two-phase strategy.

## Dataset Split

Use two plugin groups:

- Shallow/direct-file group: `crm-perks-forms`, `seo-local-rank`.
- Hook-mediated group: `photo-gallery`, `joomsport-sports-league-results-management`, `udraw`.

Shallow targets mostly prove HookPhuzz does not collapse on easy bugs. They are
not strong evidence for deep hook exploration. Hook-mediated targets are where
HookPhuzz should show value through continued callback coverage growth.

## Commands

Sanity run:

```powershell
cd phuzz-main\code
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery,crm-perks-forms -RunsPerMode 1 -RunMinutes 10 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE
```

Pilot run:

```powershell
cd phuzz-main\code
.\benchmark-wordpress-phuzz.ps1 -Plugins crm-perks-forms,photo-gallery -RunsPerMode 1 -RunHours 6 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE,HOOK_FAST -TraceMinutes 20 -FastSeedLimit 5
```

Full evaluation:

```powershell
cd phuzz-main\code
.\benchmark-wordpress-phuzz.ps1 -Plugins crm-perks-forms,seo-local-rank,photo-gallery,joomsport-sports-league-results-management,udraw -RunsPerMode 3 -RunHours 12 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE,HOOK_FAST
```

## Output To Inspect

Each run directory should contain:

- `run_manifest.json`
- `benchmark_summary.json`
- `coverage_timeline.csv`
- `coverage_timeline.json`
- `fuzzer-output/request-events.jsonl`

`HOOK_FAST` also contains:

- `trace-phase/`
- `seed-export/hook_gap_report.json`
- `seed-export/suggested_seeds.json`
- `seed-export/imported_unauth_seeds.json`
- `hook-fast-config.json`

## Acceptance Criteria

Minimum sanity criteria:

- every selected mode writes `run_manifest.json`
- every selected mode writes `benchmark_summary.json`
- every selected mode has non-zero `total_requests`
- `PHUZZ_RAW` has `requests_per_second`
- traced modes have hook request artifacts unless the run fails loudly
- `HOOK_FAST` writes seed export artifacts before starting the fast phase

Decision criteria:

- If `HOOK_TRACE` EPS is much lower than `PHUZZ_TRACE`, do not conclude the
  hook-aware algorithm is worse without also reading `HOOK_FAST`.
- If `PHUZZ_RAW` finds a bug quickly on a direct-file target, classify it as
  likely shallow until hook-mediated evidence says otherwise.
- Strong HookPhuzz evidence is a coverage timeline where callback coverage keeps
  rising after PHUZZ curves flatten, especially on hook-mediated plugins.
