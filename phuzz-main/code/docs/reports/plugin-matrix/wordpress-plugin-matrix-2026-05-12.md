# WordPress plugin matrix validation

Generated at: 2026-05-12 20:49:13 +07:00

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

- nirweb-support (SQLi): active + FUZZER_CONFIG=wordpress/nirweb-support + requests=3
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins nirweb-support
- arprice-responsive-pricing-table (SQLi): active + FUZZER_CONFIG=wordpress/arprice-responsive-pricing-table + requests=4
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins arprice-responsive-pricing-table
- ubigeo-peru (SQLi): active + FUZZER_CONFIG=wordpress/ubigeo-peru + requests=4
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins ubigeo-peru
- photo-gallery (SQLi): active + FUZZER_CONFIG=wordpress/photo-gallery + requests=41
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins photo-gallery
- show-all-comments-in-one-page (XSS): active + FUZZER_CONFIG=wordpress/show-all-comments-in-one-page + requests=46
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins show-all-comments-in-one-page
- essential-real-estate (XSS): active + FUZZER_CONFIG=wordpress/essential-real-estate + requests=37
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins essential-real-estate
- crm-perks-forms (XSS): active + FUZZER_CONFIG=wordpress/crm-perks-forms + requests=212
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins crm-perks-forms
- rezgo (XSS): active + FUZZER_CONFIG=wordpress/rezgo + requests=48
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins rezgo
- gallery-album (XSS): active + FUZZER_CONFIG=wordpress/gallery-album + requests=31
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins gallery-album
- usc-e-shop (PathTraversal): active + FUZZER_CONFIG=wordpress/usc-e-shop + requests=5
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins usc-e-shop
- udraw (PathTraversal): active + FUZZER_CONFIG=wordpress/udraw + requests=113
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins udraw
- seo-local-rank (PathTraversal): active + FUZZER_CONFIG=wordpress/seo-local-rank + requests=400
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins seo-local-rank
- hypercomments (PathTraversal): active + FUZZER_CONFIG=wordpress/hypercomments + requests=1
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins hypercomments
- nmedia-user-file-uploader (PathTraversal): active + FUZZER_CONFIG=wordpress/nmedia-user-file-uploader + requests=1
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins nmedia-user-file-uploader
- joomsport-sports-league-results-management (Deserialization): active + FUZZER_CONFIG=wordpress/joomsport-sports-league-results-management + requests=38
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins joomsport-sports-league-results-management
- totop-link (Deserialization): active + FUZZER_CONFIG=wordpress/totop-link + requests=62
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins totop-link
- webp-converter-for-media (OpenRedirect): active + FUZZER_CONFIG=wordpress/webp-converter-for-media + requests=4
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins webp-converter-for-media
- phastpress (OpenRedirect): active + FUZZER_CONFIG=wordpress/phastpress + requests=4
  run: .\run-wordpress-plugin-matrix.ps1 -DownloadMissing -Plugins phastpress

## Failed plugins

- kivicare-clinic-management-system (SQLi): Timed out waiting for http://localhost:8080/
- newsletter-optin-box (OpenRedirect): Plugin newsletter-optin-box is not active after WordPress bootstrap.
- all-in-one-wp-security-and-firewall (OpenRedirect): Failed to read active plugins.
- pie-register (OpenRedirect): Failed to read active plugins.

## Detailed results

| Plugin | Category | Status | Requests | Download | Note |
| --- | --- | --- | ---: | --- | --- |
| kivicare-clinic-management-system | SQLi | failed | 0 | existing:kivicare-clinic-management-system.zip | Timed out waiting for http://localhost:8080/ |
| nirweb-support | SQLi | success | 3 | existing:nirweb-support.zip | WordPress active and PHUZZ request trace observed. |
| arprice-responsive-pricing-table | SQLi | success | 4 | existing:arprice-responsive-pricing-table.zip | WordPress active and PHUZZ request trace observed. |
| ubigeo-peru | SQLi | success | 4 | existing:ubigeo-peru.zip | WordPress active and PHUZZ request trace observed. |
| photo-gallery | SQLi | success | 41 | existing:photo-gallery.zip | WordPress active and PHUZZ request trace observed. |
| show-all-comments-in-one-page | XSS | success | 46 | existing:show-all-comments-in-one-page.zip | WordPress active and PHUZZ request trace observed. |
| essential-real-estate | XSS | success | 37 | downloaded:essential-real-estate.zip | WordPress active and PHUZZ request trace observed. |
| crm-perks-forms | XSS | success | 212 | downloaded:crm-perks-forms.zip | WordPress active and PHUZZ request trace observed. |
| rezgo | XSS | success | 48 | downloaded:rezgo.zip | WordPress active and PHUZZ request trace observed. |
| gallery-album | XSS | success | 31 | downloaded:gallery-album.zip | WordPress active and PHUZZ request trace observed. |
| usc-e-shop | PathTraversal | success | 5 | downloaded:usc-e-shop.zip | WordPress active and PHUZZ request trace observed. |
| udraw | PathTraversal | success | 113 | downloaded:udraw.zip, downloaded:woocommerce.zip | WordPress active and PHUZZ request trace observed. |
| seo-local-rank | PathTraversal | success | 400 | existing:seo-local-rank.zip | WordPress active and PHUZZ request trace observed. |
| hypercomments | PathTraversal | success | 1 | existing:hypercomments.zip | WordPress active and PHUZZ request trace observed. |
| nmedia-user-file-uploader | PathTraversal | success | 1 | existing:nmedia-user-file-uploader.zip | WordPress active and PHUZZ request trace observed. |
| joomsport-sports-league-results-management | Deserialization | success | 38 | existing:joomsport-sports-league-results-management.zip | WordPress active and PHUZZ request trace observed. |
| totop-link | Deserialization | success | 62 | existing:totop-link.zip | WordPress active and PHUZZ request trace observed. |
| newsletter-optin-box | OpenRedirect | failed | 0 | existing:newsletter-optin-box.zip | Plugin newsletter-optin-box is not active after WordPress bootstrap. |
| webp-converter-for-media | OpenRedirect | success | 4 | existing:webp-converter-for-media.zip | WordPress active and PHUZZ request trace observed. |
| phastpress | OpenRedirect | success | 4 | existing:phastpress.zip | WordPress active and PHUZZ request trace observed. |
| all-in-one-wp-security-and-firewall | OpenRedirect | failed | 0 | existing:all-in-one-wp-security-and-firewall.zip | Failed to read active plugins. |
| pie-register | OpenRedirect | failed | 0 | existing:pie-register.zip | Failed to read active plugins. |
