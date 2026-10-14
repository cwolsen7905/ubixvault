#!/usr/bin/env bash
# Performance baseline: the same write / read / list load, through the Service
# with no client retries, against the chart on MariaDB (HA, 3 replicas) and on
# Raft (3 replicas, a PVC each) in one kind cluster, one backend at a time.
# Also checks the leader lease on real PVCs: under sustained write load the
# Raft term must not move (a missed 500ms lease would show as an election).
#
# kind runs on one CI VM and its volumes are the host's disk, so these are a
# regression baseline and a relative comparison, not capacity figures.
#
# Needs: a kind cluster from kind.yaml, the image loaded as ubixvault:e2e,
# kubectl, helm, jq. Run from the repo root.
set -euo pipefail

REPLICAS=3
WRITES_SEQ=${WRITES_SEQ:-300}
WRITES=${WRITES:-2000}
LISTS=${LISTS:-200}
CONC=${CONC:-8}
OUT=$(mktemp -d)
RESULTS=$OUT/results.md

REL=vault FULL=vault-ubixvault NS=unset
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
trap 'rc=$?; [ $rc -ne 0 ] && dump; exit $rc' EXIT

pct() { # file percentile -> milliseconds, over 2xx rows
  awk '$1 ~ /^2/ {print $2*1000}' "$1" | sort -n | awk -v p="$2" '{a[NR]=$1} END{ if(NR==0){print "n/a"; exit} i=int((p/100)*NR+0.9999); if(i<1)i=1; printf "%.1f", a[i] }'
}
errors() { awk '$1 !~ /^2/' "$1" | wc -l | tr -d ' '; }

# run_load LABEL MODE TOTAL CONC — appends a row to $RESULTS
run_load() {
  local label=$1 mode=$2 total=$3 conc=$4 f wall ok
  f=$OUT/$BACKEND-$label.txt
  k exec -i loadgen -- sh -c 'cat > /tmp/bench-load.sh' < "$HERE/bench-load.sh"
  wall=$(k exec loadgen -- sh /tmp/bench-load.sh "$mode" "$SVC" "$ROOT" "$total" "$conc" /tmp/lat | sed -n 's/^wall=//p')
  k exec loadgen -- cat /tmp/lat > "$f"
  ok=$(awk '$1 ~ /^2/' "$f" | wc -l | tr -d ' ')
  [ "$wall" -gt 0 ] || wall=1
  printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$BACKEND" "$label" "$conc" "$ok" \
    "$(errors "$f")" "$(( ok / wall ))" "$(pct "$f" 50)/$(pct "$f" 95)/$(pct "$f" 99)" "${wall}s" | tee -a "$RESULTS"
}

raft_terms() { # one "pod term" per replica
  local p
  for p in 0 1 2; do
    printf '%s-%s %s\n' "$FULL" "$p" "$(api_pod "${FULL}-$p" GET /v1/sys/metrics | awk '/^ubixvault_raft_term /{print $2}')"
  done
}

bench_backend() { # mysql|raft
  BACKEND=$1
  NS=ubixvault-bench-$BACKEND
  SVC=http://${FULL}.${NS}.svc:8200
  step "[$BACKEND] install"
  kubectl create namespace "$NS"
  k apply -f "$HERE/../ha/infra.yaml"
  k wait --for=condition=Ready pod/loadgen --timeout=300s
  k create secret generic ubixvault-kek --from-literal=auto-unseal-key="$(openssl rand -hex 32)"
  if [ "$BACKEND" = mysql ]; then
    k wait --for=condition=Ready pod -l app=mariadb --timeout=300s
    k create secret generic ubixvault-dsn --from-literal=dsn='root:root@tcp(mariadb:3306)/ubixvault?parseTime=true'
    helm install "$REL" "$CHART" -n "$NS" \
      --set image.repository=ubixvault --set image.tag=e2e --set image.pullPolicy=Never \
      --set tls.enabled=false --set devNoTLS=true --set autoUnseal.existingSecret=ubixvault-kek \
      --set storage.type=mysql --set storage.mysql.dsnSecret=ubixvault-dsn \
      --set ha.enabled=true --set replicaCount=3 --set ha.antiAffinity=hard
    k wait --for=jsonpath='{.status.phase}'=Running pod/${FULL}-0 --timeout=300s
    sleep 3
    ROOT=$(k exec ${FULL}-0 -- ubixvault operator init -address http://127.0.0.1:8200 | sed -n 's/^Initial Root Token: //p')
    [ -n "$ROOT" ] || die "init produced no root token"
    wait_for "three ready replicas" 600 all_ready
  else
    # The ha manifest also starts MariaDB; the Raft run does not use it.
    kubectl -n "$NS" delete deployment mariadb service mariadb --ignore-not-found >/dev/null
    install_raft
    raft_init_and_join
    settled
  fi
  wait_for "the Service to answer" 60 sh -c "kubectl -n $NS exec loadgen -- curl -sf -m 5 -o /dev/null -H 'X-Vault-Token: $ROOT' $SVC/v1/sys/health"
  for i in $(seq 1 100); do kv_put "list/$i" "v$i"; done

  step "[$BACKEND] load"
  if [ "$BACKEND" = raft ]; then raft_terms > "$OUT/terms-before"; cat "$OUT/terms-before"; fi
  run_load "write, 1 client" write "$WRITES_SEQ" 1
  run_load "write, $CONC clients" write "$WRITES" "$CONC"
  run_load "read, $CONC clients" read "$WRITES" "$CONC"
  run_load "list 100 keys, 4 clients" list "$LISTS" 4
  if [ "$BACKEND" = raft ]; then
    raft_terms > "$OUT/terms-after"; cat "$OUT/terms-after"
    if diff -q "$OUT/terms-before" "$OUT/terms-after" >/dev/null; then
      echo "- Raft term unchanged across the load: no election, so the 500ms leader lease held on the PVCs' fsync latency" >> "$RESULTS.notes"
    else
      echo "- Raft term MOVED during the load (leader lease missed on these volumes)" >> "$RESULTS.notes"
      fail "the Raft term changed during the load: $(paste -d' ' "$OUT/terms-before" "$OUT/terms-after" | tr '\n' ';')"
    fi
  fi
  helm uninstall "$REL" -n "$NS" >/dev/null || true
  kubectl delete namespace "$NS" --wait=true --timeout=300s >/dev/null || true
}

{
  echo "### Performance baseline: MariaDB vs Raft (kind, 3 replicas, via the Service, no retries)"
  echo
  echo "| Backend | Load | Clients | OK | Errors | req/s | p50/p95/p99 ms | Wall |"
  echo "|---|---|---|---|---|---|---|---|"
} > "$RESULTS"
: > "$RESULTS.notes"

bench_backend mysql
bench_backend raft

step "results"
cat "$RESULTS" "$RESULTS.notes"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && { cat "$RESULTS"; echo; cat "$RESULTS.notes"; } >> "$GITHUB_STEP_SUMMARY"
[ "$FAILED" -eq 0 ] || die "see FAIL lines above"
echo PASS
