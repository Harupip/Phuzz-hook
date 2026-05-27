# WordPress CVE Target Results

This folder tracks CVE-focused WordPress targets that have dedicated PHUZZ configs and validation notes.

| Target | CVE | Config | Result Notes |
| --- | --- | --- | --- |
| Booking Calendar 9.9 | CVE-2024-1207 | `fuzzer/configs/wordpress/booking-9.9-cve-2024-1207.json` | `booking-9.9-cve-2024-1207.md` |
| Booking Calendar 9.9 create-booking route | CVE-2024-1207 | `fuzzer/configs/wordpress/booking-9.9-cve-2024-1207-create-booking.json` | `booking-9.9-cve-2024-1207.md` |
| Country State City Dropdown CF7 2.7.2 states route | CVE-2024-3495 | `fuzzer/configs/wordpress/country-state-city-auto-dropdown-2.7.2-cve-2024-3495-states.json` | `country-state-city-auto-dropdown-2.7.2-cve-2024-3495.md` |
| Country State City Dropdown CF7 2.7.2 cities route | CVE-2024-3495 | `fuzzer/configs/wordpress/country-state-city-auto-dropdown-2.7.2-cve-2024-3495-cities.json` | `country-state-city-auto-dropdown-2.7.2-cve-2024-3495.md` |
| Email Subscribers by Icegram Express 5.7.14 | CVE-2024-2876 | `fuzzer/configs/wordpress/email-subscribers-5.7.14-cve-2024-2876.json` | `email-subscribers-5.7.14-cve-2024-2876.md` |
| Email Subscribers field/operator/value probes | CVE-2024-2876 | `fuzzer/configs/wordpress/email-subscribers-5.7.14-cve-2024-2876-field.json` | `email-subscribers-5.7.14-cve-2024-2876-debug.md` |
| GamiPress 7.3.1 | CVE-2024-13496 | `fuzzer/configs/wordpress/gamipress.json` | `gamipress-7.3.1-cve-2024-13496.md` |
| WP Maps 4.9.1 | CVE-2026-3222 | `fuzzer/configs/wordpress/wp-google-map-plugin-4.9.1-cve-2026-3222.json` | `wp-google-map-plugin-4.9.1-cve-2026-3222.md` |

Use the individual result notes for source/sink evidence, hook coverage evidence, and run artifact paths.
