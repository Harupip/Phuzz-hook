#!/usr/bin/env bash
set -u
apt-get update >/dev/null
apt-get install -y --no-install-recommends ca-certificates curl openssl >/dev/null
update-ca-certificates >/dev/null
echo "base=$(head -1 /etc/os-release)"
echo "time=$(date -u +%FT%TZ)"
dpkg-query -W -f='ca-certificates=${Version}\n' ca-certificates
ls -l /etc/ssl/certs/ca-certificates.crt
curl --version | head -n 1
openssl version
for host in wordpress.org github.com; do
  echo "=== CURL $host ==="
  curl -Iv --connect-timeout 20 "https://$host/" 2>&1 | sed -n '1,50p'
  echo "curl_status=${PIPESTATUS[0]}"
  echo "=== OPENSSL $host ==="
  openssl s_client -connect "$host:443" -servername "$host" -showcerts </dev/null 2>&1 | grep -E '^(depth=|verify |subject=|issuer=|Verification:|Verify return code:|Certificate chain|Server certificate)'
  echo "openssl_status=${PIPESTATUS[0]}"
done
