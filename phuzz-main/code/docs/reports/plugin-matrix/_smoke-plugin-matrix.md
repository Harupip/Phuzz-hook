# WordPress plugin matrix validation

Generated at: 2026-05-12 19:39:50 +07:00

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

- show-all-comments-in-one-page (XSS): active + FUZZER_CONFIG=wordpress/show-all-comments-in-one-page + requests=47
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins show-all-comments-in-one-page

## Failed plugins

- None

## Detailed results

| Plugin | Category | Status | Requests | Download | Note |
| --- | --- | --- | ---: | --- | --- |
| show-all-comments-in-one-page | XSS | success | 47 | existing:show-all-comments-in-one-page.zip | WordPress active and PHUZZ request trace observed. |
