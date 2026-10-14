#!/bin/sh
# Runs inside the loadgen pod (busybox sh + curl). Usage:
#   bench-load.sh <write|read|list> <service-url> <token> <total> <concurrency> <out>
# <concurrency> workers each send total/concurrency requests back to back, no
# retries. Writes "<http-code> <seconds>" per request to <out>, and prints
# wall=<seconds>. read needs keys written by an earlier write run with the same
# concurrency; list needs keys under list/ (see bench.sh).
mode=$1 url=$2 tok=$3 total=$4 conc=$5 out=$6
per=$((total / conc))
rm -f "$out" "$out".*
start=$(date +%s)
w=0
while [ "$w" -lt "$conc" ]; do
  (
    i=0
    while [ "$i" -lt "$per" ]; do
      i=$((i + 1))
      case "$mode" in
        write) curl -s -o /dev/null -m 30 -w '%{http_code} %{time_total}\n' -X POST -H "X-Vault-Token: $tok" \
                 -d '{"data":{"k":"0123456789abcdef0123456789abcdef"}}' "$url/v1/secret/data/bench/w$w-$i" ;;
        read)  curl -s -o /dev/null -m 30 -w '%{http_code} %{time_total}\n' -H "X-Vault-Token: $tok" \
                 "$url/v1/secret/data/bench/w$w-$i" ;;
        list)  curl -s -o /dev/null -m 30 -w '%{http_code} %{time_total}\n' -H "X-Vault-Token: $tok" \
                 "$url/v1/secret/metadata/list?list=true" ;;
      esac >> "$out.$w"
    done
  ) &
  w=$((w + 1))
done
wait
end=$(date +%s)
cat "$out".* > "$out"
echo "wall=$((end - start))"
