#!/usr/bin/env bash
set -euo pipefail
wp_path=/var/www/html
until mariadb-admin ping -h "$WORDPRESS_DB_HOST" -u"$WORDPRESS_DB_USER" -p"$WORDPRESS_DB_PASSWORD" --silent; do sleep 1; done
if [[ ! -f "$wp_path/wp-load.php" ]]; then cp -a /usr/src/wordpress-base/. "$wp_path/"; fi
args=(--path="$wp_path" --allow-root)
if [[ ! -f "$wp_path/wp-config.php" ]]; then wp config create "${args[@]}" --dbname="$WORDPRESS_DB_NAME" --dbuser="$WORDPRESS_DB_USER" --dbpass="$WORDPRESS_DB_PASSWORD" --dbhost="$WORDPRESS_DB_HOST" --skip-check; fi
if ! wp core is-installed "${args[@]}"; then wp core install "${args[@]}" --url="$WORDPRESS_URL" --title='HookPhuzz Phase 10 CF7 REST' --admin_user=phase10admin --admin_password=phase10admin --admin_email=phase10@example.test --skip-email; fi
mkdir -p "$wp_path/wp-content/mu-plugins" /results/runtime /shared/opcode-events
chmod 0777 /results /results/runtime /shared/opcode-events
cp /opt/lab-observer.php "$wp_path/wp-content/mu-plugins/hookphuzz-phase10-cf7-rest-observer.php"
exec apache2-foreground
