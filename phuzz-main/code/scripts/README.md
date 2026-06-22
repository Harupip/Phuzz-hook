# Script Entrypoints

Run commands from `phuzz-main/code` unless a guide says otherwise. The root scripts are stable wrappers; the files under `scripts/` contain the implementation and are easier to debug.

## Recommended Commands

| Command | Purpose | Output |
| --- | --- | --- |
| `.\run-wordpress-phuzz.ps1 -NoFollowLogs` | Start the default WordPress PHUZZ target and export live seed suggestions. | `fuzzer/output/` and `fuzzer/output/seed_generation/` |
| `.\run-wordpress-phuzz.ps1 -RunGeneratedConfigs -GeneratedConfigTimeoutSeconds 300 -NoFollowLogs` | Export hook seeds, convert supported configs, then run each generated config sequentially. | `fuzzer/output/seed_generation/generated_config_run_summary.json` |
| `.\run-wordpress-plugin-matrix.ps1 -DownloadMissing` | Validate one or more WordPress plugin targets. | `docs/reports/plugin-matrix/` |
| `.\benchmark-wordpress-phuzz.ps1 -RunsPerMode 5 -RunMinutes 30` | Compare baseline PHUZZ scoring with hook-aware scoring. | `fuzzer/output/benchmarks/` |
| `bash ./run-wordpress-phuzz.sh -NoFollowLogs` | Bash/WSL wrapper that clears old fuzzer output before delegating to PowerShell. | `fuzzer/output/` |

## Implementation Files

| File | What it does |
| --- | --- |
| `scripts/wordpress/run-wordpress-phuzz.ps1` | Host-side WordPress runner. Its default path exports live seed suggestions; opt-in batch mode also runs generated configs sequentially with a per-config timeout. |
| `scripts/wordpress/run-wordpress-phuzz.sh` | Bash helper for WSL-like shells. It stops the fuzzer service, clears `fuzzer/output`, then calls the PowerShell runner. |
| `scripts/wordpress/run-wordpress-plugin-matrix.ps1` | Plugin matrix runner. It downloads missing plugin ZIPs, generates temporary Compose overrides, runs each selected plugin, and writes Markdown/JSON reports. |
| `scripts/benchmarks/benchmark-wordpress-phuzz.ps1` | Benchmark runner. It switches scoring mode, runs repeated fuzz windows, copies artifacts, and calls the benchmark summarizer. |

Keep root wrappers in place so existing docs, shell history, and simple demos continue to work.
