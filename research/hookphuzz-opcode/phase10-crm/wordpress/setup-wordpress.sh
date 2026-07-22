#!/usr/bin/env bash
set -euo pipefail
wp --path=/var/www/html --allow-root plugin is-active crm-perks-forms
wp --path=/var/www/html --allow-root eval 'echo defined("cfx_form_plugin_dir") ? "plugin_loaded\n" : "plugin_not_loaded\n";'
wp --path=/var/www/html --allow-root core version
php -v | head -n 2
php -m | grep -x uopz
