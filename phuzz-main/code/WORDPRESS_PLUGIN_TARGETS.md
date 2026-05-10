# WordPress PHUZZ Plugin Targets

This repo has two separate things for WordPress plugin fuzzing:

- Plugin ZIPs under `web/applications/wordpress/_plugins/`, used by WordPress/WP-CLI during setup.
- PHUZZ request configs under `fuzzer/configs/wordpress/`, used by the fuzzer to know which endpoint and parameter to mutate.

## Runnable Immediately

These plugin ZIPs exist locally right now:

| Plugin | ZIP | Config | Notes |
| --- | --- | --- | --- |
| show-all-comments-in-one-page | yes | yes | Default Docker Compose and runner target. Small package. |
| seo-local-rank | yes | yes | Larger package. Docker Compose is not currently pointed at it. |
| photo-gallery | yes | yes | Larger package. Docker Compose is not currently pointed at it. |

The current default run is `show-all-comments-in-one-page`:

```powershell
cd C:\Users\chuda\OneDrive\Desktop\phuzz-hook-cv\phuzz-main\code
.\run-wordpress-phuzz.ps1 -NoFollowLogs
docker compose logs -f fuzzer-wordpress-show-all-comments-in-one-page-1
```

## Current Docker Target

`docker-compose.yml` currently points to:

- `WP_TARGET_PLUGIN=show-all-comments-in-one-page`
- `FUZZER_CONFIG=wordpress/show-all-comments-in-one-page`
- `FUZZER_COVERAGE_PATH=/var/www/html/wp-content/plugins/show-all-comments-in-one-page/`

`run-wordpress-phuzz.ps1` is also currently wired for the same default fuzzer service.

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

The helper script `web/applications/wordpress/_plugins/download-plugins.ps1` currently downloads only the small default plugin. The heavier `seo-local-rank` and `photo-gallery` download entries are intentionally commented out, but their ZIPs already exist in this checkout.
