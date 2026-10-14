#!/bin/sh
# Runs inside the loadgen pod (curlimages/curl: busybox sh). Usage:
#   writer.sh <service-url> <token>
# Writes /v1/secret/data/chaos/1, 2, 3, ... one at a time with a 3s timeout and
# no retries, appending N to /tmp/acked when the vault answers 200 or 204 and
# the attempt count to /tmp/attempts. Stops when /tmp/stop exists.
svc=$1 tok=$2
i=0
while [ ! -e /tmp/stop ]; do
  i=$((i + 1))
  c=$(curl -s -o /dev/null -m 3 -w '%{http_code}' -X POST -H "X-Vault-Token: $tok" \
    -d "{\"data\":{\"k\":\"$i\"}}" "$svc/v1/secret/data/chaos/$i")
  case "$c" in 200|204) echo "$i" >> /tmp/acked ;; esac
  echo "$i" > /tmp/attempts
  sleep 0.1
done
