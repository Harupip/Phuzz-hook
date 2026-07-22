#!/usr/bin/env bash
set -euo pipefail
args=(--path=/var/www/html --allow-root)
rm -rf /var/www/html/wp-content/plugins/contact-form-7
unzip -q /opt/contact-form-7.zip -d /var/www/html/wp-content/plugins
wp plugin activate contact-form-7 "${args[@]}"
wp user add-cap phase10admin wpcf7_read_contact_forms "${args[@]}"
wp plugin is-active contact-form-7 "${args[@]}"
wp eval 'echo "wordpress=" . get_bloginfo("version") . "\n"; echo "cf7=" . WPCF7_VERSION . "\n";' "${args[@]}"
