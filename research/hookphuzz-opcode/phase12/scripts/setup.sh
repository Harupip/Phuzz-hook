#!/usr/bin/env bash
set -euo pipefail
bash /phase11b/scripts/setup-wordpress.sh
wp plugin activate hookphuzz-phase12-fixture --allow-root --path=/var/www/html --quiet
