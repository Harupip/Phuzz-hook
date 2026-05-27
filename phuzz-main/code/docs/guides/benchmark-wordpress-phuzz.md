# Benchmark WordPress PHUZZ

Run from:

```powershell
cd phuzz-main\code
```

Use this guide when comparing original PHUZZ with hook-aware scheduling.

## Modes

`benchmark-wordpress-phuzz.ps1` supports four modes:

- `PHUZZ_RAW`: original PHUZZ, UOPZ off.
- `PHUZZ_TRACE`: original PHUZZ, UOPZ on for coverage/overhead measurement.
- `HOOK_TRACE`: hook-aware scoring, UOPZ on.
- `HOOK_FAST`: short UOPZ trace, seed export, then fast fuzz with UOPZ off.

Read `PHUZZ_RAW` as the speed baseline. Compare `PHUZZ_TRACE` and
`HOOK_TRACE` for scheduling behavior under the same tracing cost. Use
`HOOK_FAST` for the practical two-phase run.

## Runner Files

| File | Purpose |
| --- | --- |
| `benchmark-wordpress-phuzz.ps1` | Orchestrates Docker, run windows, artifact copy, summaries, and HOOK_FAST phases. |
| `benchmark-wordpress-phuzz.config.ps1` | Benchmark plugin/mode matrix. Edit this when adding supported benchmark plugins or modes. |
| `fuzzer/benchmarking/summary.py` | CLI facade for per-run and batch summaries. |
| `fuzzer/benchmarking/report.py` | CLI facade for Markdown/SVG report generation. |

The runner does not edit `fuzzer/scoring.env` during a run. Per-mode settings
are injected through temporary Compose overrides.

## Output

Default output root:

```text
fuzzer/output/benchmarks/
```

Each plugin benchmark writes:

```text
fuzzer/output/benchmarks/<timestamp>-<plugin>/
```

Each run writes:

- `run_manifest.json`
- `benchmark_summary.json`
- `coverage_timeline.csv`
- `coverage_timeline.json`
- `fuzzer-output/`
- `requests/` when UOPZ tracing is enabled

Batch outputs:

- `benchmark_results.json`
- `benchmark_results.csv`

`HOOK_FAST` also writes:

- `trace-phase/`
- `seed-export/hook_gap_report.json`
- `seed-export/suggested_seeds.json`
- `hook-fast-config.json`

## Commands

Smoke run:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery -RunsPerMode 1 -RunMinutes 10
```

Mode sanity run:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery,crm-perks-forms -RunsPerMode 1 -RunMinutes 10 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE
```

HOOK_FAST pilot:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins crm-perks-forms,photo-gallery -RunsPerMode 1 -RunHours 6 -Modes PHUZZ_RAW,PHUZZ_TRACE,HOOK_TRACE,HOOK_FAST -TraceMinutes 20 -FastSeedLimit 5
```

Tear down Compose after run:

```powershell
.\benchmark-wordpress-phuzz.ps1 -Plugins photo-gallery -RunsPerMode 1 -RunMinutes 10 -TearDownAfterBenchmark
```

## CVE Targets

CVE-focused target notes live in:

```text
docs/results/README.md
```

Use those notes when selecting benchmark plugins for vulnerability validation.
The current CVE target set covers:

- `booking` - CVE-2024-1207
- `country-state-city-auto-dropdown` - CVE-2024-3495
- `email-subscribers` - CVE-2024-2876
- `gamipress` - CVE-2024-13496
- `wp-google-map-plugin` - CVE-2026-3222

## Metrics

Primary metrics:

- `time_to_first_unique_vuln_seconds`
- `requests_to_first_unique_vuln`
- `time_to_3_unique_vulns_seconds`
- `requests_to_3_unique_vulns`
- `unique_vulns_found_within_budget`
- `requests_per_unique_vuln`
- `requests_per_second`
- `requests_per_minute`

Support metrics:

- `unique_executed_callbacks`
- `blindspots_reduced`
- `hook_signal_request_ratio`
- `uopz_overhead_ratio`
- `scheduler_decisions_with_hook_energy_ratio`
- `median_energy_delta`

`unique_vulns_found_after_30min` remains as a compatibility alias. Prefer
`unique_vulns_found_within_budget` for new analysis.

## Updating Supported Plugins

Edit:

```text
scripts/benchmarks/benchmark-wordpress-phuzz.config.ps1
```

For each plugin, keep:

- `Category`
- `Service`
- `ZipFiles`

Smoke-pass the plugin with the plugin matrix runner before adding it to long
benchmark batches.
