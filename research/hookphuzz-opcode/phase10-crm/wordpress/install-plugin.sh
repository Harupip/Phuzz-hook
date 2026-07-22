#!/usr/bin/env bash
set -euo pipefail
wp --path=/var/www/html --allow-root plugin get crm-perks-forms --field=version
wp --path=/var/www/html --allow-root plugin is-active crm-perks-forms
