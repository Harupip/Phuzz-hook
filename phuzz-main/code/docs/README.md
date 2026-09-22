# PHUZZ WordPress Docs Index

Start here when you need to run, debug, or explain the current WordPress PHUZZ setup.

## Guides

| File | Use it when |
| --- | --- |
| `guides/run-wordpress-plugins.md` | Current online-linked command, followed by clearly labeled historical matrix instructions. |
| [guides/online-linked-flow.md](guides/online-linked-flow.md) | You need the current online-linked flow, ten-step coverage, worker/replay gates, budgets, branch proposals, artifact paths, and current limitations. |
| `guides/benchmark-wordpress-phuzz.md` | Legacy benchmark notes for comparing `PHUZZ_SCORING_MODE=1` with hook-aware scoring mode `2`. |
| `guides/hook-aware-seed-generation.md` | You need to export runtime hook seed discovery artifacts and understand extracted fuzzable params. |
| `guides/multistage-hook-discovery-metadata.md` | You need to explain or verify parent/child hook metadata such as `hook_level`, `parent_callback`, and child hooks discovered during replay. |

## Reference

| File | Use it when |
| --- | --- |
| `reference/wordpress-plugin-targets.md` | You need the current plugin inventory, successful validation list, and valid plugin slugs. |
| `reference/scoring-modes-mini.md` | You need the scoring-mode switch, env variables, and code locations for scoring changes. |

## Reports

| Folder | Contains |
| --- | --- |
| `reports/plugin-matrix/` | Dated Markdown/JSON/plugin-matrix logs from real plugin validation runs. |

## Script Map

See `../scripts/README.md` for the script layout. Use root wrappers from `phuzz-main/code` for normal runs:

```powershell
.\phuzz.ps1 -PluginSlug imsanity -DryRun
.\phuzz.ps1 -PluginSlug imsanity
```

## Current verification boundary

Only online-linked is supported as the WordPress workflow; Zend is always enabled. Settings precedence: CLI > phuzz.env > loader defaults. Generated/replay libraries and historical matrix reports do not re-enable removed CLI modes.

See [Imsanity review results](../../../docs/superpowers/plans/2026-09-22-imsanity-branch-replay-results.md): three exported configs in the last recorded campaign; bulk_complete without fuzz fields is skipped, resize_image.resumable remains unverified. The last selector patch passed 128 offline tests but has no new campaign run.
