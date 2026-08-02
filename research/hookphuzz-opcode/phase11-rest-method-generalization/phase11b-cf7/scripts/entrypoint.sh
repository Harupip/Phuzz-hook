#!/usr/bin/env bash
set -euo pipefail
if [[ ! -f /var/www/html/wp-settings.php ]]; then
  cp -a /usr/src/wordpress-base/. /var/www/html/
fi
mkdir -p /var/www/html/wp-content/mu-plugins /shared-tmpfs/hook-coverage/requests /results
chmod 0777 /shared-tmpfs/hook-coverage /shared-tmpfs/hook-coverage/requests /results
exec apache2-foreground
