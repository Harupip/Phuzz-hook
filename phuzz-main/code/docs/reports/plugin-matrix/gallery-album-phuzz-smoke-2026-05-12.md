# WordPress plugin matrix validation

Generated at: 2026-05-12 21:29:54 +07:00

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

- gallery-album (XSS): active + FUZZER_CONFIG=wordpress/gallery-album + requests=66
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins gallery-album

## Failed plugins

- None

## Detailed results

| Plugin | Category | Status | Requests | Download | Note |
| --- | --- | --- | ---: | --- | --- |
| gallery-album | XSS | success | 66 | existing:gallery-album.zip | WordPress active and PHUZZ request trace observed. |
