# WordPress plugin matrix validation

Generated at: 2026-05-13 11:57:43 +07:00

Runner:

```powershell
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing
```

Success criteria:

- ZIP present or downloaded
- plugin active in WordPress
- FUZZER_CONFIG matches the plugin slug
- fuzzer emits request trace lines

## Successful plugins

- photo-gallery (SQLi): active + FUZZER_CONFIG=wordpress/photo-gallery + requests=33
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins photo-gallery

## Failed plugins

- None

## Detailed results

| Plugin | Category | Status | Requests | Download | Note |
| --- | --- | --- | ---: | --- | --- |
| photo-gallery | SQLi | success | 33 | downloaded:photo-gallery.zip | WordPress active and PHUZZ request trace observed. |
