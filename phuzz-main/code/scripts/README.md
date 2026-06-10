# Script Entrypoints

Run commands from `phuzz-main/code` unless a guide says otherwise. The root scripts are stable wrappers; the files under `scripts/` contain the implementation and are easier to debug.

## Recommended Commands

| Command | Purpose | Output |
| --- | --- | --- |
| `.\run-wordpress-phuzz.ps1 -NoFollowLogs` | Start the default WordPress PHUZZ target and export live seed suggestions. | `fuzzer/output/` and `fuzzer/output/seed_generation/` |
| `.\run-wordpress-plugin-matrix.ps1 -DownloadMissing` | Validate one or more WordPress plugin targets. | `docs/reports/plugin-matrix/` |
| `.\run-static-seed.ps1 -PluginPath <path> -PluginSlug <slug> -IncludeRest -RunAst` | Run static seed generation and optional PHP AST analysis in an isolated Docker service. | `fuzzer/output/static-seed/` |
| `.\benchmark-wordpress-phuzz.ps1 -RunsPerMode 5 -RunMinutes 30` | Compare baseline PHUZZ scoring with hook-aware scoring. | `fuzzer/output/benchmarks/` |
| `bash ./run-wordpress-phuzz.sh -NoFollowLogs` | Bash/WSL wrapper that clears old fuzzer output before delegating to PowerShell. | `fuzzer/output/` |

## Implementation Files

| File | What it does |
| --- | --- |
| `scripts/wordpress/run-wordpress-phuzz.ps1` | Host-side default WordPress runner. It checks required plugin/config files, starts Docker services, waits for WordPress, starts the fuzzer, then exports live seed suggestions. |
| `scripts/wordpress/run-wordpress-phuzz.sh` | Bash helper for WSL-like shells. It stops the fuzzer service, clears `fuzzer/output`, then calls the PowerShell runner. |
| `scripts/wordpress/run-wordpress-plugin-matrix.ps1` | Plugin matrix runner. It downloads missing plugin ZIPs, generates temporary Compose overrides, runs each selected plugin, and writes Markdown/JSON reports. |
| `scripts/static-seed/run-static-seed.ps1` | Host-side wrapper for the isolated `static-seed` Docker Compose service. It scans plugin source and writes static seed reports/configs without changing the PHUZZ runtime image. |
| `scripts/benchmarks/benchmark-wordpress-phuzz.ps1` | Benchmark runner. It switches scoring mode, runs repeated fuzz windows, copies artifacts, and calls the benchmark summarizer. |

Keep root wrappers in place so existing docs, shell history, and simple demos continue to work.
