#!/usr/bin/env bash
# Raft smoke test: a 3-node integrated-storage cluster from the Helm chart on
# kind. Brings it up (pod -0 bootstraps, -1 and -2 join with single-use tokens),
# auto-unseals, writes a secret, force-kills the leader, and reads the secret
# back through the Service from the surviving majority, then checks the killed
# node rejoins and the cluster is whole again.
#
# The raft configuration endpoint answers {"config":{...}} (Vault wraps it in
# "data"); the jq filters below accept either.
#
# Needs: a kind cluster from kind.yaml, the image loaded as ubixvault:e2e,
# kubectl, helm, jq. Run from the repo root.
set -euo pipefail

NS=ubixvault-raft-e2e
REL=vault
FULL=${REL}-ubixvault
SVC=http://${FULL}.${NS}.svc:8200
HERE=$(cd "$(dirname "$0")" && pwd)
CHART=deploy/charts/ubixvault
FAILOVER_BOUND=${FAILOVER_BOUND:-60} # seconds a read may fail after a leader kill

k() { kubectl -n "$NS" "$@"; }
# kubectl wait fails at once on a pod that does not exist yet.
wait_pod() { for _ in $(seq 1 120); do k get pod "$1" >/dev/null 2>&1 && return 0; sleep 1; done; }
step() { printf '\n=== %s\n' "$*"; }
die() { echo "FAIL: $*"; dump; exit 1; }
dump() {
  k get pods -o wide || true
  for p in 0 1 2; do echo "--- ${FULL}-$p"; k logs "${FULL}-$p" --tail=40 2>&1 || true
    echo "--- ${FULL}-$p (previous container)"; k logs "${FULL}-$p" --previous --tail=20 2>&1 || true; done
}
trap 'rc=$?; [ $rc -ne 0 ] && dump; exit $rc' EXIT

api() { # method path [body] — through the Service, as the root token
  local m=$1 p=$2; shift 2
  k exec loadgen -- curl -s -m 10 -X "$m" -H "X-Vault-Token: $ROOT" "$@" "$SVC$p"
}
api_pod() { # pod method path [body] — straight to one pod's API
  local pod=$1 m=$2 p=$3; shift 3
  k exec loadgen -- curl -s -m 10 -X "$m" -H "X-Vault-Token: $ROOT" "$@" \
    "http://${pod}.${FULL}-headless.${NS}.svc:8200$p"
}

voters() { api "GET" /v1/sys/storage/raft/configuration 2>/dev/null | jq -r '[(.data // .).config.servers[]? | select(.voter)] | length' 2>/dev/null || echo 0; }
leader_id() { api "GET" /v1/sys/storage/raft/configuration 2>/dev/null | jq -r '(.data // .).config.servers[]? | select(.leader) | .node_id' 2>/dev/null || true; }

wait_for() { # description timeout-seconds command...
  local what=$1 t=$2; shift 2
  for _ in $(seq 1 "$t"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  die "timed out waiting for $what"
}
all_ready() { [ "$(k get statefulset "$FULL" -o jsonpath='{.status.readyReplicas}')" = 3 ]; }
three_voters() { [ "$(voters)" = 3 ]; }
has_leader() { [ -n "$(leader_id)" ]; }

step "infrastructure"
kubectl create namespace "$NS"
k apply -f "$HERE/infra.yaml"
k wait --for=condition=Ready pod/loadgen --timeout=300s
k create secret generic ubixvault-kek --from-literal=auto-unseal-key="$(openssl rand -hex 32)"

step "install: storage.type=raft, 3 replicas"
helm install "$REL" "$CHART" -n "$NS" \
  --set image.repository=ubixvault --set image.tag=e2e --set image.pullPolicy=Never \
  --set tls.enabled=false --set devNoTLS=true \
  --set autoUnseal.existingSecret=ubixvault-kek \
  --set storage.type=raft --set replicaCount=3 \
  --set storage.raft.persistence.size=1Gi \
  --set storage.networkPolicy.enabled=true \
  --set ha.antiAffinity=hard
wait_pod ${FULL}-0
k wait --for=jsonpath='{.status.phase}'=Running pod/${FULL}-0 --timeout=300s
sleep 3

step "initialize on pod -0"
ROOT=$(k exec ${FULL}-0 -- ubixvault operator init -address http://127.0.0.1:8200 | sed -n 's/^Initial Root Token: //p')
[ -n "$ROOT" ] || die "init produced no root token"
k wait --for=condition=Ready pod/${FULL}-0 --timeout=300s

step "join tokens for pods -1 and -2"
secret_args=()
for i in 1 2; do
  tok=$(api_pod ${FULL}-0 POST /v1/sys/storage/raft/join-token | jq -r '.join_token // empty')
  [ -n "$tok" ] || die "no join token for pod $i"
  secret_args+=(--from-literal="${FULL}-$i=$tok")
done
k create secret generic ${FULL}-raft-join "${secret_args[@]}"

step "cluster forms"
wait_for "three ready replicas" 600 all_ready
wait_for "three voters" 120 three_voters
wait_for "a leader" 60 has_leader
echo "leader: $(leader_id)"
k get pods -o wide

# Pods must be on different nodes (hard anti-affinity), and a PVC each.
nodes=$(k get pods -l app.kubernetes.io/name=ubixvault -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u | wc -l)
[ "$nodes" = 3 ] || die "expected 3 distinct nodes, got $nodes"
pvcs=$(k get pvc -o name | wc -l)
[ "$pvcs" = 3 ] || die "expected 3 PVCs, got $pvcs"

step "write"
VAL="raft-$(date +%s)-$RANDOM"
api POST /v1/secret/data/e2e -d "{\"data\":{\"k\":\"$VAL\"}}" >/dev/null
got=$(api GET /v1/secret/data/e2e | jq -r '.data.data.k')
[ "$got" = "$VAL" ] || die "read-back before the kill: '$got' != '$VAL'"

step "kill the leader"
LEADER=$(leader_id)
echo "killing $LEADER"
k delete pod "$LEADER" --grace-period=0 --force --wait=false
start=$(date +%s)
read_back() { [ "$(api GET /v1/secret/data/e2e | jq -r '.data.data.k')" = "$VAL" ]; }
wait_for "the secret to be readable again" "$FAILOVER_BOUND" read_back
echo "readable again after $(( $(date +%s) - start ))s"
NEW=$(leader_id)
[ -n "$NEW" ] && [ "$NEW" != "$LEADER" ] || die "leader is '$NEW' (was $LEADER)"
echo "new leader: $NEW"

step "write on the new leader, then the killed node rejoins"
VAL2="after-$RANDOM"
api POST /v1/secret/data/e2e2 -d "{\"data\":{\"k\":\"$VAL2\"}}" >/dev/null
wait_for "three ready replicas again" 600 all_ready
wait_for "three voters again" 120 three_voters
for i in 0 1 2; do # every replica, standby or not, serves both values
  g=$(api_pod ${FULL}-$i GET /v1/secret/data/e2e2 | jq -r '.data.data.k')
  [ "$g" = "$VAL2" ] || die "pod $i read '$g' != '$VAL2'"
done
[ "$(api GET /v1/secret/data/e2e | jq -r '.data.data.k')" = "$VAL" ] || die "first secret lost"

step "PASS"
