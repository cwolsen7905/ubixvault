#!/bin/sh
# Runs inside the loadgen pod. Usage: verify.sh <base-url> <token>
# Reads every key in /tmp/acked from <base-url> and prints the ones that do not
# read back with the value they were written with, then "missing=<n>".
base=$1 tok=$2
missing=0
while read -r n; do
  v=$(curl -s -m 5 -H "X-Vault-Token: $tok" "$base/v1/secret/data/chaos/$n" |
    sed -n 's/.*"k":"\([^"]*\)".*/\1/p')
  if [ "$v" != "$n" ]; then
    echo "missing chaos/$n (read '$v')"
    missing=$((missing + 1))
  fi
done < /tmp/acked
echo "missing=$missing"
