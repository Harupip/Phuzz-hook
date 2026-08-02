#!/usr/bin/env bash
set -euo pipefail
cd /var/www/html
if [[ ! -f wp-config.php ]]; then
  wp --allow-root core config --dbname="$WORDPRESS_DB_NAME" --dbuser="$WORDPRESS_DB_USER" --dbpass="$WORDPRESS_DB_PASSWORD" --dbhost="$WORDPRESS_DB_HOST" --skip-check --quiet
fi
if ! wp --allow-root core is-installed >/dev/null 2>&1; then
  wp --allow-root core install --url=http://localhost --title='HookPhuzz Phase 11' --admin_user=phase11 --admin_password=phase11-local-only --admin_email=phase11@example.test --skip-email --quiet
fi
wp --allow-root plugin activate hookphuzz-phase11 --quiet
wp --allow-root option update permalink_structure '/%postname%/' --quiet
wp --allow-root rewrite flush --hard --quiet
