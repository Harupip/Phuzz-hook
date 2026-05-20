# HookPhuzz teacher report - 2026-05-22

## Current status

This branch adds the benchmark tooling needed to evaluate HookPhuzz more cleanly, but it does not yet contain final long-run evidence.

Implemented:

- Four benchmark modes: `PHUZZ_RAW`, `PHUZZ_TRACE`, `HOOK_TRACE`, and `HOOK_FAST`.
- EPS and overhead metrics through `requests_per_second`, `requests_per_minute`, and `median_uopz_overhead_ratio`.
- Per-run timeline artifacts through `coverage_timeline.csv` and `coverage_timeline.json`.
- Report generation through `benchmark_report.md` and `coverage_timeline.svg`.
- A two-phase `HOOK_FAST` strategy: short tracing with UOPZ enabled, then fast fuzzing with UOPZ disabled using generated seed config.

Not completed yet:

- No verified 4-6 hour or 12-24 hour run artifact is present in the current checkout.
- Existing benchmark artifacts are mostly 10-minute mode comparisons.
- The SVG chart is generated only after running `fuzzer/benchmarking/report.py`; the benchmark runner does not call it automatically yet.

## Code locations to show

Mode matrix:

```text
phuzz-main/code/scripts/benchmarks/benchmark-wordpress-phuzz.ps1
```

Important mode mapping:

```powershell
PHUZZ_RAW   = PHUZZ_SCORING_MODE=1, FUZZER_ENABLE_UOPZ=0
PHUZZ_TRACE = PHUZZ_SCORING_MODE=1, FUZZER_ENABLE_UOPZ=1
HOOK_TRACE  = PHUZZ_SCORING_MODE=2, FUZZER_ENABLE_UOPZ=1
HOOK_FAST   = trace phase with HOOK_TRACE, then fast phase with FUZZER_ENABLE_UOPZ=0
```

UOPZ switch:

```text
phuzz-main/code/web/instrumentation/__fuzzer__startcov.php
```

The runtime loads hook instrumentation only when:

```php
if (getenv('FUZZER_ENABLE_UOPZ') === '1') {
    include __DIR__ . "/hook_coverage/bootstrap/load_uopz_hook_coverage.php";
}
```

Scoring selector:

```text
phuzz-main/code/fuzzer/scoring.py
```

`PHUZZ_SCORING_MODE=1` selects original PHUZZ scoring.
`PHUZZ_SCORING_MODE=2` selects PHUZZ plus hook-aware feedback.

Summary metrics:

```text
phuzz-main/code/fuzzer/benchmarking/summary.py
```

Report and SVG chart:

```text
phuzz-main/code/fuzzer/benchmarking/report.py
```

## Commands

Use PowerShell from the repository's PHUZZ code directory:

```powershell
cd C:\Users\chuda\OneDrive\Desktop\phuzz-hook-cv\phuzz-main\code
```

### 1. Short smoke run

Purpose: verify Docker, WordPress, plugin setup, request events, and summary artifacts.

```powershell
.\benchmark-wordpress-phuzz.ps1 `
  -Plugins photo-gallery `
  -RunsPerMode 1 `
  -RunMinutes 10 `
  -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE
```

Expected output root:

```text
fuzzer\output\benchmarks\<timestamp>-photo-gallery
```

### 2. Pilot run

Purpose: run the first meaningful long pilot and include the two-phase `HOOK_FAST` strategy.

```powershell
.\benchmark-wordpress-phuzz.ps1 `
  -Plugins photo-gallery `
  -RunsPerMode 1 `
  -RunHours 6 `
  -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE,HOOK_FAST `
  -TraceMinutes 20 `
  -FastSeedLimit 5
```

### 3. Full evaluation shape

Purpose: evaluate both shallow/direct targets and hook-mediated targets.

```powershell
.\benchmark-wordpress-phuzz.ps1 `
  -Plugins crm-perks-forms,seo-local-rank,photo-gallery,joomsport-sports-league-results-management,udraw `
  -RunsPerMode 3 `
  -RunHours 12 `
  -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE,HOOK_FAST `
  -TraceMinutes 20 `
  -FastSeedLimit 5
```

### 4. Generate report and chart

Replace `<timestamp>-photo-gallery` with the actual benchmark output directory.

```powershell
python .\fuzzer\benchmarking\report.py `
  --benchmark-root .\fuzzer\output\benchmarks\<timestamp>-photo-gallery
```

Expected report artifacts:

```text
fuzzer\output\benchmarks\<timestamp>-photo-gallery\benchmark_results.json
fuzzer\output\benchmarks\<timestamp>-photo-gallery\benchmark_results.csv
fuzzer\output\benchmarks\<timestamp>-photo-gallery\benchmark_report.md
fuzzer\output\benchmarks\<timestamp>-photo-gallery\coverage_timeline.svg
```

## How to explain the four modes

`PHUZZ_RAW` is the original PHUZZ speed baseline. It disables UOPZ so it measures the brute-force request rate without hook tracing overhead.

`PHUZZ_TRACE` is original PHUZZ with UOPZ enabled. It shows how much overhead the hook tracing layer adds when the algorithm is still unchanged.

`HOOK_TRACE` is HookPhuzz with UOPZ enabled for the whole run. This is the direct hook-aware algorithm comparison against `PHUZZ_TRACE` under the same tracing cost.

`HOOK_FAST` is the practical two-phase prototype. It first uses UOPZ briefly to discover hook gaps, exports direct seed requests, then disables UOPZ and fuzzes faster using the generated config.

## What to report as the current conclusion

The prototype now separates three effects that were previously mixed together:

- original PHUZZ brute-force speed,
- UOPZ tracing overhead,
- hook-aware scheduling behavior.

This is enough to run a fairer experiment. The missing step is to execute a 4-6 hour pilot, then a 12-24 hour final campaign, and compare the coverage-over-time chart. The expected strong HookPhuzz evidence is a timeline where original PHUZZ plateaus early while HookPhuzz continues discovering callbacks or hook-mediated vulnerabilities.
