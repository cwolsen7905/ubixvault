# Shared helpers for the raft e2e scripts that sit beside run.sh (chaos.sh,
# migrate.sh, bench.sh). Source it; it expects NS, REL and FULL to be set.
# run.sh predates it and keeps its own copies.

SVC=http://${FULL}.${NS}.svc:8200
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CHART=deploy/charts/ubixvault
LABEL=app.kubernetes.io/name=ubixvault

k() { kubectl -n "$NS" "$@"; }
# kubectl wait fails at once on a pod that does not exist yet.
wait_pod() { for _ in $(seq 1 120); do k get pod "$1" >/dev/null 2>&1 && return 0; sleep 1; done; }
step() { printf '\n=== %s\n' "$*"; }
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
dump() {
  k get pods -o wide || true
  for p in 0 1 2; do
    echo "--- ${FULL}-$p"; k logs "${FULL}-$p" --tail=40 2>&1 || true
    echo "--- ${FULL}-$p (previous)"; k logs "${FULL}-$p" --previous --tail=20 2>&1 || true
  done
}
die() { echo "FAIL: $*"; dump; exit 1; }

# api METHOD PATH [curl args] — through the Service, as $ROOT.
api() {
  local m=$1 p=$2; shift 2
  k exec loadgen -- curl -s -m 10 -X "$m" -H "X-Vault-Token: $ROOT" "$@" "$SVC$p"
}
# api_pod POD METHOD PATH [curl args] — straight to one pod's API.
api_pod() {
  local pod=$1 m=$2 p=$3; shift 3
  k exec loadgen -- curl -s -m 10 -X "$m" -H "X-Vault-Token: $ROOT" "$@" \
    "http://${pod}.${FULL}-headless.${NS}.svc:8200$p"
}

# The configuration answers {"config":...}; Vault wraps it in "data".
config_json() { api GET /v1/sys/storage/raft/configuration 2>/dev/null || true; }
voters() { config_json | jq -r '[(.data // .).config.servers[]? | select(.voter)] | length' 2>/dev/null || echo 0; }
leader_id() { config_json | jq -r '(.data // .).config.servers[]? | select(.leader) | .node_id' 2>/dev/null || true; }
member_ids() { config_json | jq -r '(.data // .).config.servers[]?.node_id' 2>/dev/null || true; }

wait_for() { # description timeout-seconds command...
  local what=$1 t=$2; shift 2
  for _ in $(seq 1 "$t"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  die "timed out waiting for $what"
}
all_ready() { [ "$(k get statefulset "$FULL" -o jsonpath='{.status.readyReplicas}')" = "${REPLICAS:-3}" ]; }
n_voters() { [ "$(voters)" = "${REPLICAS:-3}" ]; }
has_leader() { [ -n "$(leader_id)" ]; }
settled() { wait_for "all replicas ready" 600 all_ready; wait_for "all voters" 180 n_voters; wait_for "a leader" 60 has_leader; }

# kv_put KEY VALUE / kv_get KEY — KV v2 through the Service.
kv_put() { api POST "/v1/secret/data/$1" -d "{\"data\":{\"k\":\"$2\"}}" >/dev/null; }
kv_get() { api GET "/v1/secret/data/$1" | jq -r '.data.data.k // empty'; }

install_raft() { # extra helm args...
  helm install "$REL" "$CHART" -n "$NS" \
    --set image.repository=ubixvault --set image.tag=e2e --set image.pullPolicy=Never \
    --set tls.enabled=false --set devNoTLS=true \
    --set autoUnseal.existingSecret=ubixvault-kek \
    --set storage.type=raft --set replicaCount=3 \
    --set storage.raft.persistence.size=1Gi \
    --set storage.networkPolicy.enabled=true \
    --set ha.antiAffinity=hard "$@"
}

# raft_init_and_join — initialize on pod -0, then mint join tokens for the
# others into the chart's join Secret. Sets ROOT.
raft_init_and_join() {
  wait_pod ${FULL}-0
  k wait --for=jsonpath='{.status.phase}'=Running pod/${FULL}-0 --timeout=300s
  sleep 3
  ROOT=$(k exec ${FULL}-0 -- ubixvault operator init -address http://127.0.0.1:8200 | sed -n 's/^Initial Root Token: //p')
  [ -n "$ROOT" ] || die "init produced no root token"
  k wait --for=condition=Ready pod/${FULL}-0 --timeout=300s
  local args=() i tok
  for i in $(seq 1 $(( ${REPLICAS:-3} - 1 ))); do
    tok=$(api_pod ${FULL}-0 POST /v1/sys/storage/raft/join-token | jq -r '.join_token // empty')
    [ -n "$tok" ] || die "no join token for pod $i"
    args+=(--from-literal="${FULL}-$i=$tok")
  done
  k create secret generic ${FULL}-raft-join "${args[@]}"
}

# mint_token POD — a join token from the current leader's API, for POD's key.
mint_token() {
  local leader tok
  leader=$(leader_id)
  tok=$(api_pod "$leader" POST /v1/sys/storage/raft/join-token | jq -r '.join_token // empty')
  [ -n "$tok" ] || die "no join token"
  echo "$tok"
}

node_of() { k get pod "$1" -o jsonpath='{.spec.nodeName}'; }

# The acknowledged-write recorder: writer.sh runs in the loadgen pod, putting
# /v1/secret/data/chaos/N with no retries and listing every N the vault
# acknowledged (200/204) in /tmp/acked.
start_writer() {
  k exec -i loadgen -- sh -c 'cat > /tmp/writer.sh' < "$HERE/writer.sh"
  k exec loadgen -- sh -c "rm -f /tmp/acked /tmp/stop /tmp/attempts; nohup sh /tmp/writer.sh '$SVC' '$ROOT' >/dev/null 2>&1 &"
  sleep 3
  [ "$(k exec loadgen -- sh -c 'wc -l < /tmp/acked' 2>/dev/null || echo 0)" -gt 5 ] || die "writer is not acknowledging writes"
}
stop_writer() {
  k exec loadgen -- touch /tmp/stop
  sleep 2
  echo "acknowledged writes: $(k exec loadgen -- sh -c 'wc -l < /tmp/acked') of $(k exec loadgen -- sh -c 'cat /tmp/attempts 2>/dev/null || echo ?') attempted"
}
# verify_acked [pod] — every acknowledged write must read back, through the
# Service or straight from one replica (a standby forwards, so each must).
verify_acked() {
  local base=$SVC out
  [ -n "${1:-}" ] && base="http://$1.${FULL}-headless.${NS}.svc:8200"
  k exec -i loadgen -- sh -c 'cat > /tmp/verify.sh' < "$HERE/verify.sh"
  out=$(k exec loadgen -- sh /tmp/verify.sh "$base" "$ROOT")
  echo "$out" | tail -5
  [ "$(echo "$out" | tail -n1)" = "missing=0" ] || fail "acknowledged writes lost (reading ${1:-the Service})"
}
