#!/usr/bin/env bash
set -euo pipefail
wp_path=/var/www/html
until mariadb-admin ping -h "$WORDPRESS_DB_HOST" -u "$WORDPRESS_DB_USER" -p"$WORDPRESS_DB_PASSWORD" --silent; do sleep 1; done
if [[ ! -f "$wp_path/wp-load.php" ]]; then
  mkdir -p "$wp_path"
  curl -fsSL https://wordpress.org/wordpress-6.5.5.tar.gz | tar -xz -C "$wp_path" --strip-components=1
  curl -fsSL https://github.com/wp-cli/wp-cli/releases/download/v2.10.0/wp-cli-2.10.0.phar -o /usr/local/bin/wp
  chmod +x /usr/local/bin/wp
fi
args=(--path="$wp_path" --allow-root --skip-plugins --skip-themes)
if [[ ! -f "$wp_path/wp-config.php" ]]; then wp config create "${args[@]}" --dbname="$WORDPRESS_DB_NAME" --dbuser="$WORDPRESS_DB_USER" --dbpass="$WORDPRESS_DB_PASSWORD" --dbhost="$WORDPRESS_DB_HOST" --skip-check; fi
if ! wp core is-installed "${args[@]}"; then wp core install "${args[@]}" --url="$WORDPRESS_URL" --title='HookPhuzz Phase 10' --admin_user=phase10admin --admin_password=phase10admin --admin_email=phase10@example.test --skip-email; fi
mkdir -p "$wp_path/wp-content/plugins"
rm -rf "$wp_path/wp-content/plugins/hookphuzz-phase10-controlled" "$wp_path/wp-content/plugins/hookphuzz-phase10-noise" "$wp_path/wp-content/plugins/crm-perks-forms"
cp -a /opt/phase10-controlled "$wp_path/wp-content/plugins/hookphuzz-phase10-controlled"
cp -a /opt/phase10-noise "$wp_path/wp-content/plugins/hookphuzz-phase10-noise"
cp -a /opt/crm-perks-forms "$wp_path/wp-content/plugins/crm-perks-forms"
unzip -qo /opt/contact-form-7.zip -d "$wp_path/wp-content/plugins"
mkdir -p "$wp_path/wp-content/mu-plugins"
cp /opt/phase10-discovery.php "$wp_path/wp-content/mu-plugins/hookphuzz-phase10-discovery.php"
wp plugin activate hookphuzz-phase10-controlled hookphuzz-phase10-noise crm-perks-forms contact-form-7 "${args[@]}"
wp user add-cap phase10admin cfx_form_edit_settings "${args[@]}"
exec apache2-foreground
