#!/usr/bin/env bash
set -euo pipefail
if [[ ! -f /var/www/html/wp-settings.php ]]; then cp -a /usr/src/wordpress-base/. /var/www/html/; fi
mkdir -p /var/www/html/wp-content/mu-plugins /shared-tmpfs/hook-coverage/requests /results
cp /opt/uopz_hook_wp.php /var/www/html/wp-content/mu-plugins/uopz_hook_wp.php
cp /opt/phase13-observer.php /var/www/html/wp-content/mu-plugins/phase13-observer.php
cp /opt/phase13-containment.php /var/www/html/wp-content/mu-plugins/phase13-containment.php
chmod 0777 /shared-tmpfs/hook-coverage /shared-tmpfs/hook-coverage/requests /results
exec apache2-foreground
