# WordPress plugin matrix validation

Generated at: 2026-05-13 15:46:37 +07:00

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

- crm-perks-forms (XSS): active + FUZZER_CONFIG=wordpress/crm-perks-forms + requests=171
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins crm-perks-forms
- seo-local-rank (PathTraversal): active + FUZZER_CONFIG=wordpress/seo-local-rank + requests=400
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins seo-local-rank
- totop-link (Deserialization): active + FUZZER_CONFIG=wordpress/totop-link + requests=55
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins totop-link
- webp-converter-for-media (OpenRedirect): active + FUZZER_CONFIG=wordpress/webp-converter-for-media + requests=4
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins webp-converter-for-media

## Failed plugins

- None

## Detailed results

| Plugin | Category | Status | Requests | Download | Note |
| --- | --- | --- | ---: | --- | --- |
| crm-perks-forms | XSS | success | 171 | existing:crm-perks-forms.zip | WordPress active and PHUZZ request trace observed. |
| seo-local-rank | PathTraversal | success | 400 | existing:seo-local-rank.zip | WordPress active and PHUZZ request trace observed. |
| totop-link | Deserialization | success | 55 | existing:totop-link.zip | WordPress active and PHUZZ request trace observed. |
| webp-converter-for-media | OpenRedirect | success | 4 | existing:webp-converter-for-media.zip | WordPress active and PHUZZ request trace observed. |
