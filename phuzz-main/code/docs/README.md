# PHUZZ WordPress Docs Index

Start here when you need to run, debug, or explain the current WordPress PHUZZ setup.

## Guides

| File | Use it when |
| --- | --- |
| `guides/run-wordpress-plugins.md` | You need exact commands for the default plugin, one plugin, many plugins, or the full plugin matrix. |
| [guides/online-linked-flow.md](guides/online-linked-flow.md) | You need the current online-linked flow, ten-step coverage, worker/replay gates, artifact paths, and the completion plan. |
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
.\run-wordpress-phuzz.ps1 -NoFollowLogs
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing
.\benchmark-wordpress-phuzz.ps1 -RunsPerMode 5 -RunMinutes 30
```
