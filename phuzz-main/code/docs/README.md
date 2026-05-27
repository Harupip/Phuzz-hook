# PHUZZ WordPress Docs Index

Start here when you need to run, debug, or explain the current WordPress PHUZZ setup.

## Guides

| File | Use it when |
| --- | --- |
| `guides/run-wordpress-plugins.md` | You need exact commands for the default plugin, one plugin, many plugins, or the full plugin matrix. |
| `guides/benchmark-wordpress-phuzz.md` | You need to compare PHUZZ raw/trace modes with hook-aware trace/fast modes. |

## Reference

| File | Use it when |
| --- | --- |
| `reference/wordpress-plugin-targets.md` | You need the current plugin inventory, successful validation list, and valid plugin slugs. |
| `reference/scoring-modes-mini.md` | You need the scoring-mode switch, env variables, and code locations for scoring changes. |

## Reports

| Folder | Contains |
| --- | --- |
| `results/` | Per-CVE validation notes, target configs, run evidence, and follow-up status. |
| `reports/plugin-matrix/` | Dated Markdown/JSON/plugin-matrix logs from real plugin validation runs. |

## CVE Targets

Start with `results/README.md` when reviewing the CVE-focused WordPress targets:

- `booking` - CVE-2024-1207
- `country-state-city-auto-dropdown` - CVE-2024-3495
- `email-subscribers` - CVE-2024-2876
- `gamipress` - CVE-2024-13496
- `wp-google-map-plugin` - CVE-2026-3222

## Script Map

See `../scripts/README.md` for the script and config layout. Use root wrappers from `phuzz-main/code` for normal runs:

```powershell
.\run-wordpress-phuzz.ps1 -NoFollowLogs
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing
.\benchmark-wordpress-phuzz.ps1 -RunsPerMode 5 -RunMinutes 30
```
