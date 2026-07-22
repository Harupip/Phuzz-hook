#!/usr/bin/env bash
set -euo pipefail

wp_path=/var/www/html
plugin_path="$wp_path/wp-content/plugins/hookphuzz-demo-target"
mu_plugin_path="$wp_path/wp-content/mu-plugins/hookphuzz-demo-discovery.php"
wp_args=(--path="$wp_path" --allow-root --skip-plugins --skip-themes)

until mariadb-admin ping -h "$WORDPRESS_DB_HOST" -u "$WORDPRESS_DB_USER" -p"$WORDPRESS_DB_PASSWORD" --silent; do sleep 1; done

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

mkdir -p "$(dirname "$mu_plugin_path")"
cp /opt/hookphuzz-demo-instrumentation/hookphuzz-demo-discovery.php "$mu_plugin_path"
chown www-data:www-data "$mu_plugin_path"

if ! wp core is-installed "${wp_args[@]}"; then
  wp core install "${wp_args[@]}" --url="$WORDPRESS_URL" --title='HookPhuzz Generic AJAX Demo' \
    --admin_user=hookphuzzdemo --admin_password=hookphuzzdemo --admin_email=demo@example.test --skip-email
fi

rm -rf "$plugin_path"
mkdir -p "$(dirname "$plugin_path")"
cp -a /opt/hookphuzz-demo-target "$plugin_path"
chown -R www-data:www-data "$plugin_path"
if wp plugin activate hookphuzz-demo-target "${wp_args[@]}"; then
  printf 'active\n' > /shared/plugin-active.txt
else
  printf 'inactive\n' > /shared/plugin-active.txt
fi

if php -r 'exit(extension_loaded("hookphuzz_opcode_phase9") ? 0 : 1);'; then
  printf 'loaded\n' > /shared/extension-loaded.txt
else
  printf 'missing\n' > /shared/extension-loaded.txt
fi
chmod 0644 /shared/extension-loaded.txt /shared/plugin-active.txt

exec apache2-foreground
