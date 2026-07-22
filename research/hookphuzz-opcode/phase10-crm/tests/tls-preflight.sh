#!/usr/bin/env bash
set -euo pipefail
test -s /etc/ssl/certs/ca-certificates.crt
dpkg-query -W ca-certificates
curl --fail --show-error --silent --location --connect-timeout 20 --output /dev/null https://wordpress.org/
curl --fail --show-error --silent --location --connect-timeout 20 --output /dev/null https://github.com/
echo TLS_PREFLIGHT_PASS
