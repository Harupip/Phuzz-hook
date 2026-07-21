#!/usr/bin/env bash
set -euo pipefail

wp_path=/var/www/html
plugin_path="$wp_path/wp-content/plugins/hookphuzz-phase6-fixture"
wp_args=(--path="$wp_path" --allow-root --skip-plugins --skip-themes)

until mariadb-admin ping -h "$WORDPRESS_DB_HOST" -u "$WORDPRESS_DB_USER" -p"$WORDPRESS_DB_PASSWORD" --silent; do
  sleep 1
done

if [[ ! -f "$wp_path/wp-load.php" ]]; then
  cp -a /usr/src/wordpress/. "$wp_path/"
  chown -R www-data:www-data "$wp_path"
fi

if [[ ! -f "$wp_path/wp-config.php" ]]; then
  wp config create "${wp_args[@]}" --dbname="$WORDPRESS_DB_NAME" --dbuser="$WORDPRESS_DB_USER" \
    --dbpass="$WORDPRESS_DB_PASSWORD" --dbhost="$WORDPRESS_DB_HOST" --dbprefix="$WORDPRESS_TABLE_PREFIX" --skip-check
  wp config set AUTOMATIC_UPDATER_DISABLED true --raw "${wp_args[@]}"
  wp config set WP_AUTO_UPDATE_CORE false --raw "${wp_args[@]}"
  wp config set DISABLE_WP_CRON true --raw "${wp_args[@]}"
fi

if ! wp core is-installed "${wp_args[@]}"; then
  wp core install "${wp_args[@]}" --url="$WORDPRESS_URL" --title='HookPhuzz Phase 6' \
    --admin_user=phase6admin --admin_password=phase6admin --admin_email=phase6@example.test --skip-email
fi

rm -rf "$plugin_path"
mkdir -p "$(dirname "$plugin_path")"
cp -a /opt/phase6-plugin "$plugin_path"
chown -R www-data:www-data "$plugin_path"
wp plugin activate hookphuzz-phase6-fixture "${wp_args[@]}"

exec apache2-foreground
