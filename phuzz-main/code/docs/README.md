# PHUZZ WordPress Docs Index

Start here when you need to run, debug, or explain the current WordPress PHUZZ setup.

Reviewed against working-tree source **2026-10-09**, including uncommitted batch/ZIP-directory support. [Repository entrypoint](../../../README.md) and [walkthrough](../../../wordpress-phuzz-walkthrough.md) use the same current workflow. Dated plans, handoffs, experiment configs and reports retain historical evidence.

## Guides

| File | Use it when |
| --- | --- |
| [guides/run-wordpress-plugins.md](guides/run-wordpress-plugins.md) | Single plugin, batch ZIP, preferred archive directory/fallback, env settings, non-interactive runs and result checks; historical matrix section remains labeled. |
| [guides/online-linked-flow.md](guides/online-linked-flow.md) | You need the current online-linked flow, ten-step coverage, worker/replay gates, budgets, branch proposals, artifact paths, and current limitations. |
| `guides/benchmark-wordpress-phuzz.md` | Legacy benchmark notes for comparing `PHUZZ_SCORING_MODE=1` with hook-aware scoring mode `2`. |
| `guides/hook-aware-seed-generation.md` | You need to export runtime hook seed discovery artifacts and understand extracted fuzzable params. |
| `guides/multistage-hook-discovery-metadata.md` | You need to explain or verify parent/child hook metadata such as `hook_level`, `parent_callback`, and child hooks discovered during replay. |
| [guides/zend-runtime-discovery-stage1.md](guides/zend-runtime-discovery-stage1.md) | Historical Stage 1/generated-mode contracts and fixture evidence; use online-linked for current runtime behavior. |

## Reference

| File | Use it when |
| --- | --- |
| [reference/architecture.md](reference/architecture.md) | Current feature inventory, canonical module ownership, data flow, tooling and verification boundaries. |
| `reference/wordpress-plugin-targets.md` | You need the current plugin inventory, successful validation list, and valid plugin slugs. |
| `reference/scoring-modes-mini.md` | You need the scoring-mode switch, env variables, and code locations for scoring changes. |

## Reports

| Folder | Contains |
| --- | --- |
| `reports/plugin-matrix/` | Dated Markdown/JSON/plugin-matrix logs from real plugin validation runs. |
| [reports/2026-10-09-documentation-review.md](reports/2026-10-09-documentation-review.md) | Current documentation review scope, corrected drift and checks/limitations. |

## Script Map

See `../scripts/README.md` for the script layout. Use root wrappers from `phuzz-main/code` for normal runs:

```powershell
.\phuzz.ps1 -PluginSlug imsanity -DryRun
.\phuzz.ps1 -PluginSlug imsanity
.\phuzz.ps1 -AllPlugins -DryRun
.\phuzz.ps1 -AllPlugins
```

## Current verification boundary

Only online-linked is supported as the WordPress workflow; Zend is always enabled. Settings precedence: CLI > phuzz.env > loader defaults. Generated/replay libraries and historical matrix reports do not re-enable removed CLI modes.

Read [online-linked](guides/online-linked-flow.md) for initial/hard budgets, checkpoint/resume, error-response discovery and distinct/cumulative export. PowerShell wrappers do not expose Python hard-cap/resume flags. `final-config-summary.json.exported_configs` lists active exports; `selected_version` is only a compatibility representative.

[Imsanity review results](../../../docs/superpowers/plans/2026-09-22-imsanity-branch-replay-results.md) records dated campaigns and selector checks. The flow guide also records a later historical `resumable` observation; neither record establishes acceptance of today's working tree. No plugin campaign was rerun for this documentation refresh.
