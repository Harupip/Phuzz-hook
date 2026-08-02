#!/usr/bin/env bash
set -euo pipefail
args=(--path=/var/www/html --allow-root)
cd /var/www/html
if [[ ! -f wp-config.php ]]; then
  wp core config --dbname="$WORDPRESS_DB_NAME" --dbuser="$WORDPRESS_DB_USER" --dbpass="$WORDPRESS_DB_PASSWORD" --dbhost="$WORDPRESS_DB_HOST" --skip-check --quiet "${args[@]}"
fi
for _ in $(seq 1 30); do
  wp db check "${args[@]}" >/dev/null 2>&1 && break
  sleep 1
done
wp db check "${args[@]}" >/dev/null
if ! wp core is-installed "${args[@]}" >/dev/null 2>&1; then
  wp core install --url=http://localhost --title='HookPhuzz Phase 11B' --admin_user=phase11badmin --admin_password="$PHASE11B_LOCAL_PASSWORD" --admin_email=phase11badmin@example.test --skip-email --quiet "${args[@]}"
fi
rm -rf /var/www/html/wp-content/plugins/contact-form-7
unzip -q /opt/contact-form-7.zip -d /var/www/html/wp-content/plugins
wp plugin activate contact-form-7 --quiet "${args[@]}"
for user in "$PHASE11B_LOCAL_USERNAME" "$PHASE11B_DENIED_USERNAME"; do
  if ! wp user get "$user" "${args[@]}" >/dev/null 2>&1; then
    password_var=PHASE11B_LOCAL_PASSWORD
    [[ "$user" == "$PHASE11B_DENIED_USERNAME" ]] && password_var=PHASE11B_DENIED_PASSWORD
    wp user create "$user" "$user@example.test" --role=subscriber --user_pass="${!password_var}" --quiet "${args[@]}"
  fi
done
wp user set-role "$PHASE11B_LOCAL_USERNAME" subscriber --quiet "${args[@]}"
wp user add-cap "$PHASE11B_LOCAL_USERNAME" edit_posts "${args[@]}"
wp user set-role "$PHASE11B_DENIED_USERNAME" subscriber --quiet "${args[@]}"
wp user remove-cap "$PHASE11B_DENIED_USERNAME" edit_posts "${args[@]}" >/dev/null 2>&1 || true
wp option update permalink_structure '/%postname%/' --quiet "${args[@]}"
wp rewrite flush --hard --quiet "${args[@]}"
wp eval 'if ( ! defined("WPCF7_VERSION") || WPCF7_VERSION !== "5.7.7" ) { fwrite(STDERR, "CF7 version mismatch\n"); exit(1); } echo WPCF7_VERSION;' "${args[@]}"
