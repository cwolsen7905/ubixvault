#!/usr/bin/env bash
# Migration rehearsal: MySQL (HA, 3 replicas) -> Raft (3 replicas), then back.
# docs/design/raft-storage.md, "Migrating from the MySQL backend", and
# docs/DEPLOYMENT.md, "Migrating from MySQL to Raft".
#
#   MODE=orphan    the same Helm release: delete the StatefulSet with
#                  --cascade=orphan (volumeClaimTemplates and serviceName are
#                  immutable) and `helm upgrade` to storage.type=raft.
#   MODE=parallel  a second release (vault-raft) next to the first, which is
#                  scaled to 0 and kept untouched as the rollback.
#
# Both do the same data path: freeze the MySQL release; export the ciphertext
# from the database (operator raft export-mysql, no unseal) with a count and
# digest; restore it offline into pod -0's volume (operator snapshot restore
# -storage raft); start Raft with the same auto-unseal key; join -1 and -2;
# compare engine-level reads (KV, transit, policy, a non-root token) and a
# digest of a snapshot taken from the running cluster against the export.
# Then roll back: snapshot the cluster, restore it into the emptied database,
# bring the MySQL release back, and check a write made on Raft survived.
#
# Prints the client-visible outage (freeze -> first read served by Raft) for
# the writeup. Needs: a kind cluster from kind.yaml, the image loaded as
# ubixvault:e2e, kubectl, helm, jq. Run from the repo root.
set -euo pipefail

MODE=${MODE:-orphan}
case "$MODE" in orphan|parallel) ;; *) echo "MODE must be orphan or parallel"; exit 2 ;; esac
NS=ubixvault-raft-migrate-$MODE
REPLICAS=3
OLD_REL=vault
if [ "$MODE" = orphan ]; then NEW_REL=vault; else NEW_REL=vault-raft; fi

REL=$OLD_REL FULL=$OLD_REL-ubixvault
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
trap 'rc=$?; [ $rc -ne 0 ] && dump; exit $rc' EXIT

use_release() { REL=$1; FULL=$1-ubixvault; SVC=http://${FULL}.${NS}.svc:8200; }
SUMMARY=$(mktemp)
note() { echo "$*" | tee -a "$SUMMARY"; }

mysql_args=(--set storage.type=mysql --set storage.mysql.dsnSecret=ubixvault-dsn --set ha.enabled=true --set replicaCount=3)
common=(--set image.repository=ubixvault --set image.tag=e2e --set image.pullPolicy=Never
  --set tls.enabled=false --set devNoTLS=true --set autoUnseal.existingSecret=ubixvault-kek)
raft_args=(--set storage.type=raft --set replicaCount=3 --set storage.raft.persistence.size=1Gi
  --set storage.networkPolicy.enabled=true --set ha.antiAffinity=hard)

SALT=$RANDOM
seed() {
  for i in $(seq 1 20); do kv_put "mig/$i" "value-$i-$SALT"; done
  api POST /v1/transit/keys/mig >/dev/null
  CT=$(api POST /v1/transit/encrypt/mig -d "{\"plaintext\":\"$(printf 'plain-%s' "$SALT" | base64)\"}" | jq -r '.data.ciphertext')
  [ -n "$CT" ] && [ "$CT" != null ] || die "transit encrypt failed"
  api PUT /v1/sys/policies/acl/mig -d '{"policy":"path \"secret/data/mig/*\" { capabilities = [\"read\"] }"}' >/dev/null
  T2=$(api POST /v1/auth/token/create -d '{"policies":["mig"],"ttl":"24h"}' | jq -r '.auth.client_token')
  [ -n "$T2" ] && [ "$T2" != null ] || die "token create failed"
}
verify() { # label — every engine reads back identically through the current Service
  local bad=0 i
  for i in $(seq 1 20); do [ "$(kv_get "mig/$i")" = "value-$i-$SALT" ] || { echo "kv mig/$i differs"; bad=1; }; done
  local pt
  pt=$(api POST /v1/transit/decrypt/mig -d "{\"ciphertext\":\"$CT\"}" | jq -r '.data.plaintext // empty' | base64 -d 2>/dev/null || true)
  [ "$pt" = "plain-$SALT" ] || { echo "transit decrypt: '$pt'"; bad=1; }
  [ "$(api GET /v1/sys/policies/acl/mig -o /dev/null -w '%{http_code}')" = 200 ] || { echo "policy mig missing"; bad=1; }
  local code
  code=$(k exec loadgen -- curl -s -o /dev/null -m 10 -w '%{http_code}' -H "X-Vault-Token: $T2" "$SVC/v1/secret/data/mig/1")
  [ "$code" = 200 ] || { echo "the non-root token no longer reads mig/1 (HTTP $code)"; bad=1; }
  [ "$bad" = 0 ] || die "$1: engine-level reads differ"
  echo "$1: KV x20, transit round trip, policy and token intact"
}

wait_read() { [ "$(kv_get mig/1)" = "value-1-$SALT" ]; }

step "[$MODE] infrastructure"
kubectl create namespace "$NS"
k apply -f "$HERE/../ha/infra.yaml"   # MariaDB + loadgen
k wait --for=condition=Ready pod -l app=mariadb --timeout=300s
k wait --for=condition=Ready pod/loadgen --timeout=300s
k create secret generic ubixvault-dsn --from-literal=dsn='root:root@tcp(mariadb:3306)/ubixvault?parseTime=true'
k create secret generic ubixvault-kek --from-literal=auto-unseal-key="$(openssl rand -hex 32)"

step "[$MODE] the MySQL release, seeded"
use_release "$OLD_REL"
helm install "$REL" "$CHART" -n "$NS" "${common[@]}" "${mysql_args[@]}"
k wait --for=jsonpath='{.status.phase}'=Running pod/${FULL}-0 --timeout=300s
sleep 3
ROOT=$(k exec ${FULL}-0 -- ubixvault operator init -address http://127.0.0.1:8200 | sed -n 's/^Initial Root Token: //p')
[ -n "$ROOT" ] || die "init produced no root token"
wait_for "three ready replicas" 600 all_ready
wait_for "an active replica" 120 sh -c "kubectl -n $NS exec loadgen -- curl -sf -m 5 $SVC/v1/sys/health -o /dev/null"
seed
verify "before"

step "[$MODE] does helm upgrade alone work? (it must not: volumeClaimTemplates are immutable)"
if [ "$MODE" = orphan ]; then
  if helm upgrade "$REL" "$CHART" -n "$NS" "${common[@]}" "${raft_args[@]}" --timeout 60s >/tmp/upgrade.out 2>&1; then
    fail "helm upgrade straight to raft succeeded; the recreate step may no longer be needed"
  else
    note "- plain \`helm upgrade\` to raft is refused: $(grep -o 'StatefulSet.*forbidden[^"]*' /tmp/upgrade.out | head -1 | cut -c1-160)"
  fi
fi

step "[$MODE] freeze the MySQL release"
FREEZE=$(date +%s)
k scale statefulset "$FULL" --replicas=0
wait_for "old pods gone" 300 sh -c "[ -z \"\$(kubectl -n $NS get pods -l $LABEL -o name)\" ]"

# The new release's -0 volume, pre-created under the name its StatefulSet will
# adopt, then filled by a one-shot pod: export -> restore -> digest.
NEWFULL=$NEW_REL-ubixvault
step "[$MODE] export from MySQL, restore into ${NEWFULL}-0's volume"
cat <<YAML | k apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data-${NEWFULL}-0}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: migrate-work}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: Pod
metadata: {name: migrator}
spec:
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532}
  volumes:
    - {name: work, persistentVolumeClaim: {claimName: migrate-work}}
    - {name: data, persistentVolumeClaim: {claimName: data-${NEWFULL}-0}}
  initContainers:
    - name: export
      image: ubixvault:e2e
      imagePullPolicy: Never
      args: [operator, raft, export-mysql, -storage-mysql-dsn, "root:root@tcp(mariadb:3306)/ubixvault?parseTime=true", /work/mysql.snap]
      volumeMounts: [{name: work, mountPath: /work}]
    - name: restore
      image: ubixvault:e2e
      imagePullPolicy: Never
      args: [operator, snapshot, restore, -storage, raft, -data, /var/lib/ubixvault,
             -raft-node-id, ${NEWFULL}-0,
             -raft-advertise-addr, "${NEWFULL}-0.${NEWFULL}-headless.${NS}.svc:8201", /work/mysql.snap]
      volumeMounts: [{name: work, mountPath: /work}, {name: data, mountPath: /var/lib/ubixvault}]
  containers:
    - name: digest
      image: ubixvault:e2e
      imagePullPolicy: Never
      args: [operator, raft, digest, /work/mysql.snap]
      volumeMounts: [{name: work, mountPath: /work}]
YAML
wait_for "migrator to finish" 300 sh -c "[ \"\$(kubectl -n $NS get pod migrator -o jsonpath='{.status.phase}')\" = Succeeded ]"
k logs migrator -c export
k logs migrator -c restore
EXPORT_DIGEST=$(k logs migrator -c digest | sed -n 's/^sha256 //p')
EXPORT_COUNT=$(k logs migrator -c digest | sed -n 's/^entries //p')
[ -n "$EXPORT_DIGEST" ] && [ "${EXPORT_COUNT:-0}" -gt 0 ] || die "no export digest"
note "- exported $EXPORT_COUNT entries, sha256 ${EXPORT_DIGEST:0:16}…"
k delete pod migrator --wait=false

step "[$MODE] start Raft"
if [ "$MODE" = orphan ]; then
  k delete statefulset "$FULL" --cascade=orphan
  helm upgrade "$REL" "$CHART" -n "$NS" "${common[@]}" "${raft_args[@]}"
else
  helm install "$NEW_REL" "$CHART" -n "$NS" "${common[@]}" "${raft_args[@]}"
fi
use_release "$NEW_REL"
k wait --for=jsonpath='{.status.phase}'=Running pod/${FULL}-0 --timeout=300s
k wait --for=condition=Ready pod/${FULL}-0 --timeout=300s
wait_for "the data to be served by Raft" 120 wait_read
OUTAGE=$(( $(date +%s) - FREEZE ))
note "- client-visible outage (freeze -> first read served by Raft on -0): ${OUTAGE}s"
verify "after cutover, one voter"

step "[$MODE] join -1 and -2"
args=()
for i in 1 2; do
  tok=$(api_pod ${FULL}-0 POST /v1/sys/storage/raft/join-token | jq -r '.join_token // empty')
  [ -n "$tok" ] || die "no join token for pod $i"
  args+=(--from-literal="${FULL}-$i=$tok")
done
k create secret generic ${FULL}-raft-join "${args[@]}"
settled
verify "after joining, three voters"

step "[$MODE] a snapshot of the running cluster holds every exported entry"
# Taken before any write on Raft. A running cluster adds a few entries of its
# own on start and may re-encrypt some (listed); none may be missing.
cat <<YAML | k apply -f -
apiVersion: v1
kind: Pod
metadata: {name: digest-post}
spec:
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532}
  volumes: [{name: work, persistentVolumeClaim: {claimName: migrate-work}}]
  initContainers:
    - name: fetch
      image: curlimages/curl:8.10.1
      command: [sh, -c, "curl -sf -m 120 -H 'X-Vault-Token: ${ROOT}' ${SVC}/v1/sys/storage/raft/snapshot -o /work/post.snap"]
      volumeMounts: [{name: work, mountPath: /work}]
  containers:
    - name: compare
      image: ubixvault:e2e
      imagePullPolicy: Never
      args: [operator, raft, digest, -against, /work/mysql.snap, /work/post.snap]
      volumeMounts: [{name: work, mountPath: /work}]
YAML
wait_for "digest-post to finish" 180 sh -c "p=\$(kubectl -n $NS get pod digest-post -o jsonpath='{.status.phase}'); [ \"\$p\" = Succeeded ] || [ \"\$p\" = Failed ]"
k logs digest-post -c compare | tee /tmp/compare.out
if [ "$(k get pod digest-post -o jsonpath='{.status.phase}')" = Succeeded ]; then
  note "- migrated cluster vs export: $(tr '\n' ' ' < /tmp/compare.out | grep -o 'missing [0-9]* changed [0-9]* added [0-9]*')"
else
  fail "the migrated cluster lost entries of the export"
fi
k delete pod digest-post --wait=false >/dev/null

step "[$MODE] rollback: Raft -> MySQL"
kv_put post-cutover "after-$SALT"
RB=$(date +%s)
k exec deploy/mariadb -- mariadb -uroot -proot -e 'DROP DATABASE ubixvault; CREATE DATABASE ubixvault;'
cat <<YAML | k apply -f -
apiVersion: v1
kind: Pod
metadata: {name: rollback}
spec:
  restartPolicy: Never
  securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532}
  volumes: [{name: work, emptyDir: {}}]
  initContainers:
    - name: fetch
      image: curlimages/curl:8.10.1
      command: [sh, -c, "curl -sf -m 120 -H 'X-Vault-Token: ${ROOT}' ${SVC}/v1/sys/storage/raft/snapshot -o /work/raft.snap"]
      volumeMounts: [{name: work, mountPath: /work}]
  containers:
    - name: restore
      image: ubixvault:e2e
      imagePullPolicy: Never
      args: [operator, snapshot, restore, -storage, mysql, -storage-mysql-dsn, "root:root@tcp(mariadb:3306)/ubixvault?parseTime=true", /work/raft.snap]
      volumeMounts: [{name: work, mountPath: /work}]
YAML
wait_for "rollback restore to finish" 180 sh -c "[ \"\$(kubectl -n $NS get pod rollback -o jsonpath='{.status.phase}')\" = Succeeded ]"
k delete pod rollback --wait=false >/dev/null
k scale statefulset "$FULL" --replicas=0
wait_for "raft pods gone" 300 sh -c "[ -z \"\$(kubectl -n $NS get pods -l $LABEL,app.kubernetes.io/instance=$NEW_REL -o name)\" ]"
if [ "$MODE" = orphan ]; then
  k delete statefulset "$FULL" --cascade=orphan
  helm upgrade "$REL" "$CHART" -n "$NS" "${common[@]}" "${mysql_args[@]}"
else
  use_release "$OLD_REL"
  k scale statefulset "$FULL" --replicas=3
fi
use_release "$OLD_REL"
wait_for "three ready MySQL replicas" 600 all_ready
wait_for "the data to be served by MySQL again" 180 wait_read
note "- rollback: MySQL release serving again ${RB:+$(( $(date +%s) - RB ))s} after the snapshot was taken"
verify "after rollback"
[ "$(kv_get post-cutover)" = "after-$SALT" ] || fail "the write made on Raft is missing after rollback"

step "results"
cat "$SUMMARY"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### MySQL -> Raft migration rehearsal ($MODE)"; echo; cat "$SUMMARY"; } >> "$GITHUB_STEP_SUMMARY"
fi
[ "$FAILED" -eq 0 ] || die "see FAIL lines above"
echo PASS
