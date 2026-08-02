#!/usr/bin/env bash
set -euo pipefail
if [[ ! -f /var/www/html/wp-settings.php ]]; then cp -a /usr/src/wordpress-base/. /var/www/html/; fi
exec apache2-foreground
