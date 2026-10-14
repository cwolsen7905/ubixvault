#!/usr/bin/env bash
# Raft chaos suite on kind (docs/design/raft-storage.md, Testing 5). One
# three-node cluster, one client writing through the Service the whole time
# with no retries, and every write the vault acknowledged must read back at the
# end of every scenario:
#
#   1. leader freeze      docker pause on the leader's kind node (a hung host)
#   2. partition          iptables DROP on the leader's node between its pod
#                         and the other two (no CNI change needed)
#   3. full restart       scale to 0 and back; PVCs kept, auto-unseal
#   4. PVC loss, pod -2   remove-peer, wipe, re-join with a fresh token
#   5. PVC loss, pod -0   the guard: -0 must NOT bootstrap a second cluster
#                         under its old ID; it joins once given a token
#
# Needs: a kind cluster from kind.yaml (docker on the host, node containers
# named after the nodes), the image loaded as ubixvault:e2e, kubectl, helm, jq.
# Run from the repo root.
set -euo pipefail

NS=ubixvault-raft-chaos
REL=vault
FULL=${REL}-ubixvault
REPLICAS=3
FREEZE_BOUND=${FREEZE_BOUND:-45}     # seconds until another node leads
PARTITION_BOUND=${PARTITION_BOUND:-45}
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
trap 'rc=$?; [ $rc -ne 0 ] && dump; exit $rc' EXIT

SUMMARY=$(mktemp)
note() { echo "$*" | tee -a "$SUMMARY"; }

wait_leader_not() { # pod — until some other node leads
  local old=$1 cur
  for _ in $(seq 1 "$2"); do
    cur=$(leader_id)
    if [ -n "$cur" ] && [ "$cur" != "$old" ]; then echo "$cur"; return 0; fi
    sleep 1
  done
  return 1
}
# Voters as the leader sees them, ignoring a frozen or partitioned node that
# answers the Service with its stale view: ask the pods we expect to be live.
ensure_not_leader() { # pod — step down if it leads
  if [ "$(leader_id)" = "$1" ]; then
    api_pod "$1" PUT /v1/sys/step-down >/dev/null
    wait_leader_not "$1" 60 >/dev/null || die "$1 would not step down"
  fi
}

step "infrastructure"
kubectl create namespace "$NS"
k apply -f "$HERE/infra.yaml"
k wait --for=condition=Ready pod/loadgen --timeout=300s
k create secret generic ubixvault-kek --from-literal=auto-unseal-key="$(openssl rand -hex 32)"
install_raft
raft_init_and_join
settled
kv_put seed v0
echo "leader: $(leader_id)"
start_writer

# ---------------------------------------------------------------- 1. freeze
step "1. leader freeze"
OLD=$(leader_id); NODE=$(node_of "$OLD"); OLDIP=$(k get pod "$OLD" -o jsonpath='{.status.podIP}')
echo "freezing $NODE (leader $OLD)"
t0=$(date +%s)
docker pause "$NODE"
NEW=$(wait_leader_not "$OLD" "$FREEZE_BOUND") || { docker unpause "$NODE"; die "no new leader within ${FREEZE_BOUND}s of freezing $OLD"; }
took=$(( $(date +%s) - t0 ))
note "- leader freeze: new leader $NEW after ${took}s (bound ${FREEZE_BOUND}s)"
kv_put during-freeze "$RANDOM"
sleep 5
docker unpause "$NODE"
# The thawed leader still believes it leads until its first heartbeat round;
# a write sent to it must be refused or forwarded to the real leader, never
# applied on a stale term. Whatever it answers, the value must be readable
# through the cluster, or the write must not have been acknowledged.
for i in 1 2 3; do
  code=$(k exec loadgen -- curl -s -o /dev/null -m 10 -w '%{http_code}' -X POST -H "X-Vault-Token: $ROOT" \
    -d "{\"data\":{\"k\":\"thaw$i\"}}" "http://$OLDIP:8200/v1/secret/data/thawed/$i" || true)
  case "$code" in
    200|204) [ "$(kv_get "thawed/$i")" = "thaw$i" ] || fail "thawed leader acknowledged thawed/$i but it is not in the cluster" ;;
  esac
  echo "thawed leader answered $code for thawed/$i"
done
settled
note "- leader freeze: the thawed node rejoined; voters back to $(voters)"

# ------------------------------------------------------------- 2. partition
step "2. partition the leader from the other two"
L=$(leader_id); LNODE=$(node_of "$L"); LIP=$(k get pod "$L" -o jsonpath='{.status.podIP}')
OTHERS=$(k get pods -l "$LABEL" -o jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' | awk -v l="$L" '$1!=l{print $2}')
part() { # -I|-D
  for ip in $OTHERS; do
    docker exec "$LNODE" iptables -w "$1" FORWARD -s "$ip" -d "$LIP" -j DROP
    docker exec "$LNODE" iptables -w "$1" FORWARD -s "$LIP" -d "$ip" -j DROP
  done
}
echo "isolating $L ($LIP) on $LNODE from: $OTHERS"
t0=$(date +%s)
part -I
NEW=$(wait_leader_not "$L" "$PARTITION_BOUND") || { part -D; die "no new leader within ${PARTITION_BOUND}s of partitioning $L"; }
note "- partition: majority elected $NEW after $(( $(date +%s) - t0 ))s"
kv_put during-partition "$RANDOM"
# The isolated former leader must refuse writes (it steps down within the lease).
sleep 5
for i in 1 2 3; do
  code=$(k exec loadgen -- curl -s -o /dev/null -m 10 -w '%{http_code}' -X POST -H "X-Vault-Token: $ROOT" \
    -d '{"data":{"k":"minority"}}' "http://$LIP:8200/v1/secret/data/minority/$i" || true)
  case "$code" in 200|204) fail "isolated minority leader $L acknowledged a write (HTTP $code)" ;; esac
  echo "isolated $L answered $code"
done
sleep 10
part -D
settled
note "- partition: healed; $L is a member again, voters $(voters), no write acknowledged by the minority"

# --------------------------------------------------------- stop the writer
stop_writer
verify_acked
for p in 0 1 2; do verify_acked "${FULL}-$p"; done
[ "$FAILED" -eq 0 ] || die "acknowledged writes lost after freeze/partition"
note "- freeze + partition: every acknowledged write reads back from every replica"
start_writer

# --------------------------------------------------------- 3. full restart
step "3. full-cluster restart (scale 0 -> 3, PVCs kept)"
kv_put before-restart "r$RANDOM"
BEFORE=$(kv_get before-restart)
stop_writer
k scale statefulset "$FULL" --replicas=0
wait_for "pods gone" 300 sh -c "[ -z \"\$(kubectl -n $NS get pods -l $LABEL -o name)\" ]"
t0=$(date +%s)
k scale statefulset "$FULL" --replicas=3
wait_for "replicas ready" 600 all_ready
wait_for "a leader" 120 has_leader
note "- full restart: leader and all ready ${REPLICAS} replicas $(( $(date +%s) - t0 ))s after scale-up (auto-unseal)"
settled
[ "$(kv_get before-restart)" = "$BEFORE" ] || fail "value written before the restart is gone"
verify_acked
for p in 0 1 2; do verify_acked "${FULL}-$p"; done
start_writer

# ------------------------------------------------------ 4. PVC loss, pod -2
wipe_and_rejoin() { # ordinal
  local pod=${FULL}-$1
  ensure_not_leader "$pod"
  api POST /v1/sys/storage/raft/remove-peer -d "{\"server_id\":\"$pod\"}" >/dev/null || die "remove-peer $pod"
  local tok; tok=$(mint_token)
  # The join Secret is read when the pod starts, so update it first.
  kubectl -n "$NS" patch secret "${FULL}-raft-join" --type merge \
    -p "{\"data\":{\"$pod\":\"$(printf %s "$tok" | base64 | tr -d '\n')\"}}" >/dev/null
  k delete pvc "data-$pod" --wait=false
  k delete pod "$pod" --grace-period=0 --force --wait=false
}
step "4. PVC loss on pod -2: remove-peer, wipe, re-join"
t0=$(date +%s)
wipe_and_rejoin 2
settled
note "- PVC loss (pod -2): wiped and re-joined, $(voters) voters, $(( $(date +%s) - t0 ))s"
[ "$(kv_get seed)" = v0 ] || fail "seed lost after pod -2 rejoin"
[ "$(api_pod ${FULL}-2 GET /v1/secret/data/seed | jq -r '.data.data.k // empty')" = v0 ] || fail "re-joined pod -2 does not serve the data"

# ------------------------------------------------------ 5. PVC loss, pod -0
step "5. PVC loss on pod -0: it must not found a second cluster"
POD0=${FULL}-0
ensure_not_leader "$POD0"
api POST /v1/sys/storage/raft/remove-peer -d "{\"server_id\":\"$POD0\"}" >/dev/null || die "remove-peer $POD0"
# No token for -0 yet (an earlier one was burned at install): the guard must
# refuse to bootstrap rather than come up as a fresh single-voter cluster.
kubectl -n "$NS" patch secret "${FULL}-raft-join" --type json -p "[{\"op\":\"remove\",\"path\":\"/data/$POD0\"}]" >/dev/null 2>&1 || true
k delete pvc "data-$POD0" --wait=false
k delete pod "$POD0" --grace-period=0 --force --wait=false
refused() { k logs "$POD0" --tail=200 2>/dev/null | grep -q "refusing to bootstrap" ||
            k logs "$POD0" --previous --tail=200 2>/dev/null | grep -q "refusing to bootstrap"; }
wait_for "-0 to refuse bootstrapping" 180 refused
[ "$(k get pod "$POD0" -o jsonpath='{.status.containerStatuses[0].ready}')" != true ] || fail "-0 is Ready without having joined"
# The other two keep serving; no second cluster appeared under -0's ID.
kv_put during-guard "$RANDOM"
ids=$(member_ids | grep -c "^$POD0$" || true)
[ "$ids" = 0 ] || fail "-0 is in the configuration without joining ($ids)"
note "- PVC loss (pod -0): refused to bootstrap while an initialized cluster answered; cluster kept writing on 2 voters"
# Now the operator's remedy: a token under -0's name.
tok=$(mint_token)
kubectl -n "$NS" patch secret "${FULL}-raft-join" --type merge \
  -p "{\"data\":{\"$POD0\":\"$(printf %s "$tok" | base64 | tr -d '\n')\"}}" >/dev/null
k delete pod "$POD0" --grace-period=0 --force --wait=false
settled
[ "$(api_pod "$POD0" GET /v1/secret/data/seed | jq -r '.data.data.k // empty')" = v0 ] || fail "re-joined pod -0 does not serve the data"
[ "$(member_ids | grep -c "^$POD0$")" = 1 ] || fail "$POD0 appears $(member_ids | grep -c "^$POD0$") times in the configuration"
note "- PVC loss (pod -0): joined with a token, voters $(voters), data served"

stop_writer
verify_acked
for p in 0 1 2; do verify_acked "${FULL}-$p"; done

step "results"
cat "$SUMMARY"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### Raft chaos (kind, 3 replicas, one write / 100ms through the Service, no retries)"; echo; cat "$SUMMARY"; } >> "$GITHUB_STEP_SUMMARY"
fi
[ "$FAILED" -eq 0 ] || die "see FAIL lines above"
echo PASS
