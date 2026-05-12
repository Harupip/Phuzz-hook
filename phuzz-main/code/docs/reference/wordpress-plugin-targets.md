# WordPress PHUZZ Plugin Targets

This repo has two separate things for WordPress plugin fuzzing:

- Plugin ZIPs under `web/applications/wordpress/_plugins/`, used by WordPress/WP-CLI during setup.
- PHUZZ request configs under `fuzzer/configs/wordpress/`, used by the fuzzer to know which endpoint and parameter to mutate.

## Runnable Immediately

The default single-plugin run is still `show-all-comments-in-one-page`:

```powershell
cd phuzz-main\code
.\run-wordpress-phuzz.ps1 -NoFollowLogs
docker compose logs -f fuzzer-wordpress-plugin
```

The repo now also has a matrix runner for non-default plugins:

```powershell
cd phuzz-main\code
.\run-wordpress-plugin-matrix.ps1 -DownloadMissing
```

That runner downloads missing ZIPs, rewires Docker to one plugin at a time, and marks a plugin as "success" only when:

- the ZIP exists locally
- the plugin becomes active in WordPress
- `FUZZER_CONFIG` matches the plugin slug
- PHUZZ emits request trace lines for that plugin

## Validated Matrix (2026-05-12)

Current local ZIP inventory is no longer only 3 files. The `_plugins` folder now contains ZIPs for all 22 PHUZZ plugin targets plus `woocommerce.zip` for `udraw`.

The latest validation report is:

- [../reports/plugin-matrix/wordpress-plugin-matrix-2026-05-12.md](../reports/plugin-matrix/wordpress-plugin-matrix-2026-05-12.md)
- [../reports/plugin-matrix/wordpress-plugin-matrix-2026-05-12.json](../reports/plugin-matrix/wordpress-plugin-matrix-2026-05-12.json)

Summary from that run:

- `18` plugins succeeded
- `4` plugins failed

Successful plugins:

- `nirweb-support`
- `arprice-responsive-pricing-table`
- `ubigeo-peru`
- `photo-gallery`
- `show-all-comments-in-one-page`
- `essential-real-estate`
- `crm-perks-forms`
- `rezgo`
- `gallery-album`
- `usc-e-shop`
- `udraw`
- `seo-local-rank`
- `hypercomments`
- `nmedia-user-file-uploader`
- `joomsport-sports-league-results-management`
- `totop-link`
- `webp-converter-for-media`
- `phastpress`

Failed plugins in that run:

- `kivicare-clinic-management-system` (`Timed out waiting for http://localhost:8080/`)
- `newsletter-optin-box` (`Plugin newsletter-optin-box is not active after WordPress bootstrap.`)
- `all-in-one-wp-security-and-firewall` (`Failed to read active plugins.`)
- `pie-register` (`Failed to read active plugins.`)

## Current Docker Target

`docker-compose.yml` currently points to:

- `WP_TARGET_PLUGIN=show-all-comments-in-one-page`
- `FUZZER_CONFIG=wordpress/show-all-comments-in-one-page`
- `FUZZER_COVERAGE_PATH=/var/www/html/wp-content/plugins/show-all-comments-in-one-page/`

`run-wordpress-phuzz.ps1` is also currently wired for the generic `fuzzer-wordpress-plugin` service.

## All PHUZZ WordPress Configs

These are the WordPress plugin targets with request configs already present under `fuzzer/configs/wordpress/`.

| Plugin | Category from init notes | Method | Target | Main fuzz field |
| --- | --- | --- | --- | --- |
| kivicare-clinic-management-system | SQLi | GET | `/wp-admin/admin-ajax.php` | `query: props_doctor_id` |
| nirweb-support | SQLi | POST | `/wp-admin/admin-ajax.php` | body/form fields |
| arprice-responsive-pricing-table | SQLi | POST | `/wp-admin/admin-ajax.php` | body/form fields |
| ubigeo-peru | SQLi | POST | `/wp-admin/admin-ajax.php` | body/form fields |
| photo-gallery | SQLi | POST | `/wp-admin/admin-ajax.php` | body/form fields |
| show-all-comments-in-one-page | XSS | GET | `/wp-admin/admin-ajax.php` | `query: post_type` |
| essential-real-estate | XSS | GET | `/wp-admin/admin-ajax.php` | `query: columns_gap` |
| crm-perks-forms | XSS | GET | `/wp-content/plugins/crm-perks-forms/templates/sample_file.php` | `query: FirstName, LastName, Company` |
| rezgo | XSS | GET | `/wp-content/plugins/rezgo/rezgo/templates/default/frame_header.php` | `query: tags` |
| gallery-album | XSS | GET | `/wp-admin/admin-ajax.php` | `query: gallery_current_index` |
| usc-e-shop | Path traversal / file access | GET | `/wp-content/plugins/usc-e-shop/functions/content-log.php` | `query: logfile` |
| udraw | Path traversal / file access | POST | `/wp-admin/admin-ajax.php` | body/form fields |
| seo-local-rank | Path traversal / file access | POST | `/wp-content/plugins/seo-local-rank/admin/vendor/datatables/examples/resources/examples.php` | body/form fields |
| hypercomments | Path traversal / file deletion | GET | `/` | `query: xml` |
| nmedia-user-file-uploader | Path traversal / file rename | POST | `/index.php?rest_route=/wpfm/v1/file-rename` | body/form fields |
| joomsport-sports-league-results-management | Deserialization | POST | `/wp-admin/admin-ajax.php` | body/form fields |
| totop-link | Deserialization | GET | `/wp-content/plugins/totop-link/totop-link.css.php` | `query: vars` |
| newsletter-optin-box | Open redirect | GET | `/` | `query: to` |
| webp-converter-for-media | Open redirect | GET | `/wp-content/plugins/webp-converter-for-media/includes/passthru.php` | `query: src` |
| phastpress | Open redirect | GET | `/wp-content/plugins/phastpress/phast.php` | `query: src` |
| all-in-one-wp-security-and-firewall | Open redirect | GET | `/` | `query: after_logout` |
| pie-register | Open redirect | GET | `/` | `query: redirect_to` |

## To Run Other Plugins

For plugins other than the default, make sure the matching ZIP exists in:

```text
web/applications/wordpress/_plugins/
```

Then point the Docker setup at the same slug in all relevant places:

- `WP_TARGET_PLUGIN`
- `FUZZER_CONFIG`
- `FUZZER_COVERAGE_PATH`
- fuzzer service name and sync volume name if you want clean per-plugin Compose services

For repeat runs, prefer `run-wordpress-plugin-matrix.ps1` over hand-editing Compose files. The detailed success/failure list above is generated from actual Docker/PHUZZ runs, not from the static config list alone.
