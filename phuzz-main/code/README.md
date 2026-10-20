# PHUZZ WordPress workspace

Reviewed against working-tree source: **2026-10-09**. The supported WordPress workflow is **online-linked**. Zend discovery and CMPLOG are enabled by the runner. Retired wrapper modes: `default`, `seed-config`, `generated`, `zend`, `online`.

## Run

Run from this directory with Docker Desktop/Compose, PowerShell 7, Python and the dependencies in [fuzzer/requirements.txt](fuzzer/requirements.txt). The checked-in WordPress application also needs `web/applications/wordpress/wp-cli.phar` and `fuzzer/configs/wordpress/bootstrap-generated.json`.

```powershell
pwsh -NoProfile -File ./phuzz.ps1 -PluginSlug imsanity -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug imsanity
pwsh -NoProfile -File ./phuzz.ps1 -AllPlugins -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -AllPlugins
```

Prepare `<slug>.zip` in `PLUGIN_ZIP_DIR` from [phuzz.env](phuzz.env), or `web/applications/wordpress/_plugins/`. Paths in the setting are absolute or relative to this directory. A single-plugin run falls back per archive to `_plugins`; batch reads only the selected directory, sorts direct ZIP files by name and runs them sequentially. No matching manual plugin config is required. Dry-run only prints the delegated command.

Flags override `phuzz.env`, then loader defaults. `Online*` flags set initial budgets; verified progress can extend them to separate hard caps. Python coordinator exposes hard-cap and resume flags; PowerShell does not. See the [run guide](docs/guides/run-wordpress-plugins.md) for ZIP names, prerequisites, prompts, batch failures and bounded automation.

## Documentation

| Document | Purpose |
| --- | --- |
| [Docs index](docs/README.md) | Current guides, reference and historical reports. |
| [Online-linked flow](docs/guides/online-linked-flow.md) | Runtime correlation, probe/trial, replay/Pass 2, handoff, budgets, resume, output and failure reasons. |
| [Architecture](docs/reference/architecture.md) | Feature inventory, canonical modules, data flow and shared/legacy tooling. |
| [Script map](scripts/README.md) | Root wrappers and implementation scripts. |
| [Fuzzer](fuzzer/README.md) | Mutation, hook scoring, CMPLOG, findings and worker output. |
| [Config schema](fuzzer/configs/README.md) | Fixed/fuzz regex selectors, request buckets and generated-config semantics. |
| [Final config export](fuzzer/online_linked/README.md) | Distinct contexts, cumulative supersession and re-export. |
| [Config comparison](fuzzer/config_comparison/README.md) | Offline comparison and interactive final-config prompt. |
| [Web instrumentation](web/README.md) | UOPZ, Zend image and WordPress setup boundaries. |

## Components and auxiliary tools

The runner starts database/web/bootstrap worker, exports runtime seed/registry snapshots, then delegates to the coordinator. Candidates are processed sequentially, with AJAX first. The coordinator gates v0, reads exact request/Zend pairs, probes pending input in the parent, verifies coherent input and child replay/Pass 2, then stops parent before starting the child. Config versions are immutable.

[HARgen](hargen/README.md) converts captured HAR requests to configs; [crawler](crawler/README.md) captures HAR; [Composegen](composegen/README.md) creates Compose files for manual configurations or multiple fuzzer instances. These are separate tools. Their presence does not enable retired wrapper modes or supply online-linked admission gates. Manual Compose commands use the checked-in `web/Dockerfile`; the runner supplies an override for `web/Dockerfile.zend`.

The underlying fuzzer still supports automated login scripts, manual JSON configs, coverage synchronization and vulnerability checkers. Generated runtime configs preserve auth context and fixed platform fields; they do not prepare arbitrary plugin state or run every login flow automatically. Generic multi-instance support does not mean online-linked runs multiple active workers per candidate.

## Output and evidence

Read `fuzzer/output/online-linked/<run-id>/batch-state.json`, then each candidate's `state_path`. Export writes `final-config-summary.json` and flat `final-configs/*.json`; the summary's `exported_configs` lists every active config. Compatible older exports can move to `final-configs/superseded/` on re-export/resume.

Worker output lives at `fuzzer/output/workers/fuzzer-N/` and is reset on startup for the same node ID. PowerShell keeps host campaign folders; runtime shared-volume artifacts are reset before a new campaign. The Bash wrapper clears host `fuzzer/output` before delegating, so use PowerShell when retaining evidence.

Exit code 0, HTTP 200, callback reachability, final config export or budget exhaustion do not prove fuzzing PASS. Separate runtime reads, replay/Pass 2, worker activity, coverage/CMPLOG and reproduced findings. This documentation refresh does not build images or rerun plugin campaigns.

Original PHUZZ paper context and citation: [project README](../README.md).
