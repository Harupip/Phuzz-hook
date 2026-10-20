# Script Entrypoints

Run commands from `phuzz-main/code` unless a guide says otherwise. The root scripts are stable wrappers; the files under `scripts/` contain the implementation and are easier to debug.

Reviewed 2026-10-09, including working-tree batch/ZIP changes. Settings: CLI flags override `phuzz.env`, then loader defaults. Initial budgets and adaptive hard caps differ; see [budget and failure reference](../docs/guides/online-linked-flow.md). Matrix/benchmark commands below are separate legacy tooling, not additional online-linked modes or runtime proof.

## Recommended Commands

| Command | Purpose | Output |
| --- | --- | --- |
| `.\phuzz.ps1 -PluginSlug gamipress` | Bootstrap WordPress and run the online-linked campaign with Zend discovery enabled. | `fuzzer/output/online-linked/<run-id>/batch-state.json` |
| `.\phuzz.ps1 -PluginSlug gamipress -DryRun` | Inspect the delegated command and resolved budgets. | Console |
| `.\phuzz.ps1 -AllPlugins -DryRun` / `.\phuzz.ps1 -AllPlugins` | Preview/run direct ZIP files in the selected folder sequentially; continue after runner errors, suppress comparison prompt. | One online-linked run folder per plugin; batch exit 1 if any runner failed. |
| `.\compare-configs.ps1` | Compare the expected/actual paths configured in `phuzz.env` offline. | Console; comparator exit 0/1/2. |
| `.\run-wordpress-plugin-matrix.ps1 -DownloadMissing` | Validate one or more WordPress plugin targets. | `docs/reports/plugin-matrix/` |
| `.\benchmark-wordpress-phuzz.ps1 -RunsPerMode 5 -RunMinutes 30` | Compare baseline PHUZZ scoring with hook-aware scoring. | `fuzzer/output/benchmarks/` |
| `bash ./run-wordpress-phuzz.sh -NoFollowLogs` | Bash/WSL wrapper that clears old fuzzer output before delegating to PowerShell. | `fuzzer/output/` |

## Implementation Files

| File | What it does |
| --- | --- |
| `scripts/wordpress/read-phuzz-env.ps1` | Parse env, resolve validated settings and select preferred ZIP with per-plugin fallback. |
| `scripts/wordpress/run-wordpress-phuzz.ps1` | Bootstrap WordPress, export runtime seeds, initialize the callback registry and invoke online-linked. |
| `scripts/wordpress/invoke-online-linked.ps1` | Stop the bootstrap worker and launch `python -m online_linked` with campaign budgets. |
| `scripts/wordpress/run-wordpress-phuzz.sh` | Bash helper for WSL-like shells. It stops the fuzzer service, clears `fuzzer/output`, then calls the PowerShell runner. |
| `scripts/wordpress/run-wordpress-plugin-matrix.ps1` | Plugin matrix runner. It downloads missing plugin ZIPs, generates temporary Compose overrides, runs each selected plugin, and writes Markdown/JSON reports. |
| `scripts/benchmarks/benchmark-wordpress-phuzz.ps1` | Benchmark runner. It switches scoring mode, runs repeated fuzz windows, copies artifacts, and calls the benchmark summarizer. |

Keep root wrappers in place so existing docs, shell history, and simple demos continue to work.

`PLUGIN_ZIP_DIR` is absolute or relative to `phuzz-main/code`. Single-plugin/menu paths fall back to `_plugins`; `-AllPlugins` enumerates only the selected folder (or `_plugins` when unset), without recursion. No manual config with the plugin's slug is required. `-ForcePlugins` applies only to the default download script.

Single-plugin runs can ask for final-config comparison when `ONLINE_COMPARE_PROMPT=1`; non-interactive input skips it. `-NoFollowLogs` does not disable that prompt. `-NoComparePrompt` is available on the direct runner and is automatically set by `-AllPlugins`. The wrapper does not expose `--resume`, custom hard caps or runtime COOKIE opt-in; those belong to the Python coordinator.

Online-linked is the only supported WordPress workflow. `-Mode online-linked` remains accepted; `default`, `seed-config`, `generated`, `zend` and `online` are removed. `-UseZendDiscovery` and `-NoFollowLogs` remain accepted for existing linked commands. Direct runner calls no longer take any `-Run*` selector; remove `-RunOnlineLinked` from old direct calls. This also prevents PowerShell from accepting the retired `-RunOnline` flag as an abbreviation. Zend is always enabled. Generated replay and Zend libraries remain shared runtime dependencies, not selectable modes. Historical guides may contain commands that are no longer supported.
