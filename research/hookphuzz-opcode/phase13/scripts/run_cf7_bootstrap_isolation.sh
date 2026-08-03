#!/usr/bin/env bash
set -Eeuo pipefail
exec "$(dirname "$0")/run_plugin_bootstrap_isolation.sh" contact-form-7 contact-form-7.zip 5.7.7 913583ac1d590daac3971791d6b5441d4d4293c60ff4ec62978c88f4d45a4461
