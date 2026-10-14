# Design note: Integrated storage (Raft)

> **Status:** Proposed · 2026-10-13 · ADR: [D-023](../DECISIONS.md) (library and
> engine choice). Builds on [D-021](../DECISIONS.md) /
> [`ha-active-standby.md`](ha-active-standby.md); relates to `docs/ROADMAP.md`
> ("Optional — only if the external database should go away"). Slices 1, 2
> (core) and part of 3 are built; see [Implementation status](#implementation-status).

## Goal

Run a uBixVault cluster whose **only** durable dependency is its own disks:
replicated storage inside the vault processes, no MySQL/MariaDB behind it. A
cluster of 3 (or 5) replicas keeps serving through the loss of a minority, with
the same active/standby model, the same Vault-compatible wire API, and the same
barrier-above-storage trust model as today.

### Goals

- **A third storage backend, `-storage raft`**, selected like `file` and `mysql`.
  Engines, auth methods, the barrier and the API are untouched.
- **Replication with no external database:** every replica holds a full copy of
  the (encrypted) store on its own PVC; a write is acknowledged only after a
  quorum has it durably.
- **Fits D-021, does not replace it:** Raft leadership *is* the HA lock; the Raft
  term *is* the fencing generation. Standby forwarding, the cluster listener,
  `sys/leader`, `sys/step-down`, health codes, PDB and readiness all carry over.
- **Vault-compatible operator surface:** `sys/storage/raft/*` and
  `operator raft …` with Vault's shapes (D-003).
- **Operable by the people who run it today:** snapshot save/restore, a documented
  migration from MySQL, a documented quorum-loss recovery, and a rollback.
- **Small code, small dependency growth:** `hashicorp/raft` and bbolt, nothing
  else on the data path; the in-house exporter (D-012) and parsers stay.

### Non-goals

- **Multi-active serving / performance standbys.** Still one active writer
  (D-021). Raft makes them *possible* later (see
  [CAS and transactions](#future-cas-and-transactions)); this note does not
  build them.
- **Cross-cluster replication, DR clusters, read replicas in other regions.**
  That is the Enterprise replication item.
- **Replacing the file backend.** Single-node `-storage raft` is allowed, but
  `file` remains the zero-dependency default for development and the smallest
  installs.
- **Removing MySQL support.** The SQL backend stays supported; it is also the
  migration source and the rollback target.
- **Hiding storage keys.** Keys (paths) are visible to anyone with disk access,
  exactly as with the file and MySQL backends; values are ciphertext. See
  [Encryption at rest](#encryption-at-rest).
- **Autopilot parity** (dead-server cleanup, upgrade migrations, redundancy
  zones). A small in-house subset only; see [Membership](#cluster-membership).

## What HA relies on MySQL for today

From D-021 and the code (`internal/storage/{mysql,mysql_lock,ha}.go`):

| Concern | Today (MySQL) | With Raft |
| --- | --- | --- |
| Data durability and replication | `ubixvault_kv` table; the database's own replication | FSM on every replica; quorum commit |
| Leader election | `ubixvault_lock` row, `UPDATE … WHERE expires_at < NOW(6)`, DB clock | Raft leader election |
| Fencing token | `generation` column, checked in every write transaction | Raft term + "must be leader to commit" |
| Planned handoff | `Release` clears the holder; standby retries (~0.5s) | `LeadershipTransfer` to a named, caught-up voter |
| Unplanned failover | lock TTL 15s + retry ≈ ≤16s | election timeout; a few seconds (to be measured) |
| Clock dependence | DB `NOW(6)` | none for safety; lease-based reads use the monotonic clock |
| External dependency | MySQL/MariaDB HA service | none |

Everything above the storage layer — standby forwarding over the mTLS cluster
listener, the cluster CA in the barrier, health parameters, `sys/leader`,
step-down, the per-replica caches reset on `becomeActive` — is
storage-independent and is reused as is. D-021 deliberately made core see only
`HABackend`; this note cashes that in.

## Library choice

**Decision (D-023): `github.com/hashicorp/raft`, with `raft-boltdb/v2` for the
log and stable store.**

| Option | For | Against |
| --- | --- | --- |
| **`hashicorp/raft`** | Same library (and operational model) as Vault integrated storage, so Vault's operator concepts — peers, `peers.json` recovery, snapshots, non-voters, leadership transfer — map one-to-one. Ships transport, snapshot store, membership changes, pre-vote, leader lease and `LeadershipTransfer`. Already named in `DESIGN.md` as a first-class library. Production-hardened at much larger scale than ours. | Adds a dependency set (go-hclog, go-msgpack, armon/go-metrics, boltdb, and their transitives); the exact `go mod graph` delta is measured in slice 1 and recorded in the ADR. Its logging/metrics shims must be adapted to our `log` and in-house exporter. |
| `etcd-io/raft` | Smaller, very well tested core; used by etcd/CockroachDB. | It is a *state machine library only*: no transport, no snapshot store, no storage, no membership workflow. We would write and own all of that — most of the risk of an in-house Raft, in the least visible places. |
| In-house Raft | Zero new dependencies; fits the "readable in an afternoon" posture (D-009/D-011/D-012). | Consensus is the hardest code in the project; a bug here is silent data loss in a secrets manager. D-009 carved out Shamir because it is small and well-specified; Raft is neither. Rejected on risk. |

The dependency posture (two third-party modules today, D-010/D-018) is the
honest cost. It is bounded by keeping the library **behind one package**
(`internal/storage/raft`): nothing outside it imports `hashicorp/raft`, and
the log/stable store sits behind an interface so `raft-boltdb/v2` can be swapped
for `hashicorp/raft-wal` if bbolt log performance or file growth ever matters.

## Storage engine, FSM, log and snapshot format

### Two bbolt files per node

```
<data-dir>/
  raft/
    raft.db          # raft-boltdb/v2: log + stable store (term, vote)
    snapshots/       # hashicorp/raft FileSnapshotStore (retain 2)
  fsm.db             # bbolt: the replicated key/value state
```

- **`fsm.db`** is the applied state machine: one bucket, `key → value`, keys in
  byte order. bbolt's B+tree gives ordered range scans, so `List(prefix)` is a
  cursor seek plus the existing `childUnder` reduction — byte-for-byte the same
  semantics as the file/memory/MySQL backends, enforced by the same conformance
  suite (`storagetest`). Keys are binary-compared (no collation hazard, cf. the
  MySQL `VARBINARY` decision); the 768-byte max key length is kept so a store
  moves between backends losslessly in either direction.
- **`raft.db`** is the Raft log, current term and vote, via `raft-boltdb/v2`.
- **Why bbolt, not Pebble/BadgerDB:** a secrets store is read-dominant, small
  (megabytes to low gigabytes), and low write volume. bbolt is a single pure-Go
  file with ACID transactions and MVCC read transactions (which give us
  consistent snapshots for free), and it is what `raft-boltdb` already uses — one
  engine, one failure model, one set of operational lore. An LSM (Pebble) buys
  write throughput we do not need and costs compaction tuning, a much larger
  dependency, and more moving parts to explain in a security review. Revisit only
  if profiling in slice 8 shows the write path is the bottleneck.
- **`fsm.db` sync:** every apply is its own bbolt `Update` with fsync on (default
  `NoSync=false`). Raft may re-apply from its log after a crash, so the FSM also
  records the last applied index in the same transaction, and `Apply` is
  idempotent for an index it has already seen.

### Commands and the FSM

Log entries are small, **versioned** command records:

```
{ version: 1, op: put | delete | (reserved: txn), key, value }
```

- `Backend.Put/Delete` marshal a command and call `raft.Apply` on the leader with
  a timeout; they return once the entry is committed and applied locally.
- The FSM is **deterministic**: no clocks, no randomness, no I/O besides its own
  bbolt file. Anything time- or ID-dependent is decided by the leader *before*
  the command is proposed.
- **FSM apply failure is fail-stop.** If a node cannot apply a committed entry
  (disk full, corrupted file), it must not skip it — that would silently fork its
  state. It marks itself failed, steps down if leader, seals, and reports
  unhealthy; it is repaired by `remove-peer` + re-join (a fresh copy) or restore.
- **Unknown command versions are refused,** and a leader only proposes an op once
  every voter has advertised support for it (rolling-upgrade gate), so a mixed
  cluster never half-applies a new command.

### Reads

- **Standbys** never serve data reads (they forward; D-021 §4). The few
  storage reads a standby does locally (`seal-status`, initialized check) read
  its own FSM, which is a consistent but possibly slightly stale prefix of the
  log.
- **The active** reads its local FSM. Two guards keep that linearizable enough
  for the single-writer rules of D-021:
  1. On becoming leader, call `raft.Barrier()` and do not mark active until it
     returns, so the FSM contains every previously committed write.
  2. `hashicorp/raft` leaders step down if they cannot reach a quorum within
     `LeaderLeaseTimeout`, bounding how long a partitioned former leader can serve
     a stale read to that lease (default 500ms) — and any *write* from it fails.
- **Decision-bearing reads** — response-wrapping unwrap (Get then Delete), token
  use-count — must not return a value unless the following write commits. The
  slice that wires `HABackend` audits those call sites. `wrapping.Unwrap`
  already returns the payload only after its `Delete` succeeds (under a mutex,
  D-021 prerequisite 1), so a deposed leader cannot hand out a second copy; the
  audit confirms the same shape everywhere else. A
  `ConsistentGet` (leader `VerifyLeader` round-trip) is available for call sites
  that need it.

### Snapshot format

- **Raft-internal snapshots** (log compaction, new-follower catch-up) stream the
  FSM under a bbolt read transaction — a point-in-time MVCC view, so writes
  continue during the snapshot — in the **existing `ubixvault-snapshot v1`
  NDJSON format** (`internal/snapshot`). Raft's snapshot store keeps the
  index/term/configuration metadata beside it.
- **One format everywhere.** An `operator raft snapshot save` file is the same
  artifact as `operator snapshot save` against the file or MySQL backend, and
  `operator snapshot restore` already knows how to read it. That is what makes
  migration, backup and rollback one mechanism rather than three
  ([Migration](#migrating-from-the-mysql-backend)).
- **Not byte-compatible with HashiCorp Vault's snapshots** (they are a different
  archive). Compatibility is at the API level — `GET/POST
  sys/storage/raft/snapshot` and the CLI shape — not the file format; a Vault
  snapshot is not restorable here, and vice versa. Documented, as it already is
  for `sys/snapshot`.
- Snapshot cadence uses `hashicorp/raft` defaults (threshold 8192 entries,
  interval 2 min, 10240 trailing logs) until measurement says otherwise. A very
  long bbolt read transaction delays free-page reuse, so snapshot duration is a
  metric (`ubixvault_raft_snapshot_seconds`).

## Encryption at rest

**The barrier stays above storage, unchanged.** Every value is AES-256-GCM
ciphertext before it reaches `Backend.Put` (DESIGN §3.2), so the Raft log,
`raft.db`, `fsm.db`, raft snapshots, operator snapshots, and every network frame
between peers carry only ciphertext. There is **no new at-rest key** and no
second encryption layer to rotate, escrow or lose.

Properties worth stating plainly, because Raft changes who holds copies:

- **Every replica's PVC holds a full copy of the ciphertext.** A stolen volume is
  equivalent to a stolen MySQL dump or file-backend directory: useless without
  the unseal shares / auto-unseal KEK. Volume-level encryption from the storage
  class is defence in depth, recommended, not required.
- **Keys (paths) are plaintext** in all three backends, as today. This is a
  known property of the storage layer and is documented in `SECURITY.md`; this
  design does not change it.
- **Peer traffic is encrypted and authenticated** (below) even though payloads are
  already ciphertext, so a network observer cannot learn write timing/keys or
  inject entries.
- **No plaintext secret ever enters a Raft structure:** log entries, snapshot
  metadata and the server configuration contain only ciphertext, keys, node IDs
  and addresses.
- **Replicated state needing the barrier** (the cluster CA, join-token hashes,
  audit HMAC key) is stored *inside* the barrier like any other secret.

## Cluster membership

### Identity and addressing

- **Node ID = pod name** (`ubixvault-0`…), stable across reschedules; set with
  `-raft-node-id` (default: hostname).
- **Address = a stable DNS name** (`<pod>.<headless-svc>.<ns>.svc:8201`),
  advertised with `-raft-advertise-addr`. D-021 chose raw pod IPs; that is not
  enough here because the address is *persisted in the Raft configuration* and a
  rescheduled pod gets a new IP. See [Kubernetes](#kubernetes-deployment).
- Quorum is counted over **voters**; 3 voters tolerate 1 failure, 5 tolerate 2.
  Even sizes are refused by the chart (and warned by the server).

### Bootstrap (first node)

`-storage raft` on an empty data directory starts as a **single-voter cluster**
(`raft.BootstrapCluster` with itself) — there is nothing to wait for, so
`sys/init` works exactly as on the other backends and a one-node Raft is a valid
(non-HA) deployment. Bootstrap is only ever done on a node with an empty
`raft.db`; a node with prior state never bootstraps, so two empty nodes cannot
accidentally form two clusters (the chart bootstraps `-0` only; others
join). `operator raft` refuses to bootstrap a node that has a join token.

### Join (everyone else)

1. On the active: `operator raft join-token` (ACL `sys/storage/raft/join-token`,
   `sudo`) mints a **single-use, short-TTL token** (default 15 min); only its
   hash is stored, in the barrier.
2. On the new node: `operator raft join -token T -leader-ca-cert <file>
   https://leader:8200`, or declaratively `-raft-retry-join` (a list of leader
   API addresses; the chart uses the headless-Service names of earlier ordinals
   and a Secret holding the token / CA).
3. The new node calls `POST sys/storage/raft/join` on the leader with its node
   ID, advertise address and token, over TLS verified against the pinned CA.
4. The leader verifies and burns the token, `AddNonvoter`s the node, and returns
   a **bridge credential**: a 24h leaf from the cluster CA (below) for the
   joiner's Raft transport.
5. The joiner replicates the log/snapshot as a **non-voter** (it can serve no
   decisions, so a slow or broken join cannot hurt quorum). When it is caught up
   (within N entries for 10s — an in-house loop on the leader, not
   `raft-autopilot`), the leader **promotes** it to voter.
6. The node is still sealed. It is then unsealed normally: auto-unseal (the
   recommended mode, and the only one that is unattended), or Shamir shares *of
   the existing cluster* on every replica, as in D-021.

Why a token and not "anyone with the CA can join": joining hands out a copy of
the whole ciphertext store and a vote. The token is an explicit, auditable,
operator-initiated grant; it is one more step than Vault's challenge/seal-wrap
flow, in exchange for a join that does not depend on the seal type.

### Leave, remove, replace

- `operator raft remove-peer <id>` (`sudo`): `RemoveServer` via the leader; the
  removed node is fenced off by losing its cluster-CA leaf trust at the next
  rotation and by no longer being in the configuration. Refused if it would
  drop below a majority of the remaining voters.
- **Graceful leave:** on `SIGTERM` a leader first transfers leadership
  (`LeadershipTransfer`), then exits; it stays a member (a StatefulSet pod is
  coming back). Scale-down is an explicit `remove-peer` before shrinking
  `replicaCount`.
- **Replacing a node:** wipe its PVC, start it, re-join with a fresh token under
  the same node ID (the stale server entry is replaced). No data restore needed;
  it catches up from the leader.
- **Dead-server cleanup** is manual in v1 and surfaced in
  `autopilot/state` (`healthy:false`, `last_contact`). Automatic removal is
  deliberately off: with a PVC-backed StatefulSet, "dead" usually means
  "rescheduling".

### Operator API surface (Vault-compatible)

Same paths, parameters and response shapes as Vault where Vault has an
equivalent (D-003); marked rows are uBixVault extensions.

| Method / path | Purpose | ACL |
| --- | --- | --- |
| `GET sys/storage/raft/configuration` | `{config:{servers:[{node_id,address,leader,protocol_version,voter}],index}}` | ACL |
| `POST sys/storage/raft/join` | `{leader_api_addr, leader_ca_cert, retry, non_voter, node_id?}` → `{joined}`. Unauthenticated by Vault token; **authenticated by the join token (ext. field `join_token`)** | join token |
| `POST sys/storage/raft/join-token` *(ext.)* | mint a single-use join token | `sudo` |
| `POST sys/storage/raft/remove-peer` | `{server_id}` | `sudo` |
| `GET sys/storage/raft/snapshot` | stream a snapshot (same artifact as `sys/snapshot`) | ACL |
| `POST sys/storage/raft/snapshot` | restore (preserves current membership) | `sudo` |
| `POST sys/storage/raft/snapshot-force` | restore even when the snapshot's cluster does not match | `sudo` |
| `GET sys/storage/raft/autopilot/state` | subset: `healthy`, `leader`, per-server `{status, healthy, last_index, last_contact, voter}` | ACL |
| `GET/POST sys/storage/raft/autopilot/configuration` | subset: promotion threshold/stabilization only | ACL |

CLI: `ubixvault operator raft list-peers | join | remove-peer | join-token |
snapshot save|restore | autopilot state`, in the shape of
`vault operator raft …`. The existing `sys/snapshot` and
`operator snapshot` stay and remain valid on every backend.

`sys/leader`, `sys/health`, `sys/step-down` need no change: step-down becomes a
`LeadershipTransfer` (preserving the "never leave the vault with no active
replica" rule — it transfers only to a caught-up voter, and falls back to
stepping down and re-electing if none is available).

## TLS between peers

Raft peers and request-forwarding peers are the same trust domain, so **Raft
rides the existing cluster listener and cluster CA** (D-021 §4) — no new
operator-supplied certificates, no cert-manager, no shared secret.

- **One port, two protocols, ALPN-multiplexed:** the cluster listener (8201,
  TLS 1.3, client cert required) dispatches on ALPN — `ubixvault-raft/1` goes to
  a `raft.StreamLayer`; the existing forwarding protocol is unchanged. The
  Service/NetworkPolicy surface does not grow.
- **Identity:** the same CA in the barrier (`sys/ha/cluster-ca`); each unsealed
  replica issues itself a short-lived in-memory leaf at half-life. A peer is
  accepted if its leaf chains to the CA — so only a process that unsealed *this*
  vault, or a joiner holding a leader-issued bridge leaf, can speak Raft.
- **Raft transport starts after unseal**, using the self-issued leaf. (A node
  restarting with an intact local FSM unseals from local state, then rejoins
  consensus; a *fresh* joiner is the only case that runs transport sealed, and
  it uses the 24h bridge leaf from the join response.) Consequence, stated
  plainly: **a sealed replica does not vote**. Quorum is over *unsealed*
  voters; with Shamir seals an operator must unseal enough replicas after a
  full restart. Auto-unseal makes this automatic.
- **Rotation / revocation:** leaves are short-lived, so removal from the
  configuration plus the next leaf cycle ends a node's access; a suspected CA
  compromise needs a cluster-CA rotation that also re-seats Raft peers. No
  rotation procedure is documented for `sys/ha/cluster-ca` today, so one is
  added in slice 5 (the CA is regenerated on the next activation if its record
  is deleted — to be confirmed against `internal/cluster`).
- **Bootstrap window:** before first unseal after `init`, a single node has no
  CA and no peers; the transport is simply not listening. The CA is created at
  init (barrier exists) and the node issues its first leaf at first unseal.

## Leader forwarding and the HA/standby model

Raft is the *election and fencing* mechanism; nothing above it changes.

```
core ── HABackend.HALock(...) ──► raft.Lock
                                  Acquire: block until raft leader AND Barrier() applied
                                  lost:    closed when LeaderCh → false / term changes
                                  Holder:  leader ID + advertise (replicated record)
                                  Release: LeadershipTransfer, then steps down
writes ── Backend.Put/Delete ──► raft.Apply (fails if not leader ⇒ ErrFenced)
```

- **Leadership = active.** `Acquire` returns when this node is Raft leader and
  its FSM is caught up; `becomeActive` runs as today (reset caches, start the
  lease sweeper). Raft nodes only exist among unsealed replicas, so the leader
  is always unsealed — the "unsealed standby" invariant of D-021 holds by
  construction.
- **Generation = Raft term.** `Holder.Generation` carries the term at election;
  it is monotonic. A deposed leader's `Apply` cannot commit (no quorum, wrong
  term), so `ErrFenced` is returned and it steps down — **fencing is a property
  of the log**, no extra read-before-write transaction (the MySQL path's
  per-write `SELECT … LOCK IN SHARE MODE` cost disappears).
- **Holder address:** the new leader writes `{id, advertise, cluster_addr}` to a
  replicated record under a reserved prefix outside the barrier's namespace
  before `Acquire` returns, so `sys/leader` and standby forwarding find it from
  any replica, even through a leadership change mid-request.
- **Forwarding is unchanged:** a standby forwards over the cluster listener
  exactly as D-021 §4, including the 5s hold across handoffs. Raft RPCs and
  forwarded HTTP share the listener but not the code path.
- **Single-node Raft:** a one-voter cluster is leader immediately; `-storage
  raft` implies HA mode (no separate `-ha` flag needed; `-ha` with raft is
  accepted and a no-op). The `-ha-lock-ttl`/`-ha-retry-interval` flags are
  meaningless for Raft and ignored with a log line; Raft's own timers are
  `-raft-heartbeat-timeout`, `-raft-election-timeout`, `-raft-leader-lease`.
- **Pre-vote and stability:** enable `hashicorp/raft` pre-vote so a node that was
  merely partitioned does not force a term bump on rejoin (which would depose a
  healthy leader).

## Snapshots, backup and restore

- **Backup:** `operator raft snapshot save` (or the existing `operator snapshot
  save`) against the active — a consistent point-in-time copy, taken from a bbolt
  read transaction without pausing writes. The chart's backup CronJob keeps
  working unchanged because the API and artifact are the same; with Raft it is
  also the only supported *logical* backup (copying a live `fsm.db`/`raft.db`
  from a volume is **not** a backup).
- **What a snapshot does not contain:** Raft membership, node identities and
  term. A snapshot is data, not topology — which is why restore is safe to apply
  to a cluster with different members.
- **Online restore** (`POST sys/storage/raft/snapshot`, `sudo`): leader replaces
  the replicated state and followers install it; current membership is kept.
  Requires an initialized, unsealed cluster and a root-capable token. The
  restored store needs *its* unseal shares / KEK (as today). Implementation
  uses the library's leader-driven restore (`raft.Restore`); verifying it
  forces followers through install-snapshot is an acceptance test in slice 3.
- **Offline restore** (`operator snapshot restore -storage raft -data <dir>`):
  for an *uninitialized* target (new cluster, migration, total loss). Builds
  `fsm.db` and a Raft snapshot + bootstrap configuration for a single voter at
  index 1, so the node comes up as a one-node cluster holding the data; others
  then join and replicate from it.
- **Quorum loss:** with a majority of voters permanently gone, the survivor is
  recovered offline with `operator raft recover -peers <file>`
  (the `peers.json` mechanism of `hashicorp/raft`): it rewrites the
  configuration on a stopped node, which then boots as the new, smaller cluster;
  the others are wiped and re-joined. Documented with the loud warning that
  this can lose writes that were acknowledged only by the dead majority.
- **Automated, off-node:** the existing `backup` values remain the answer;
  upload to object storage stays a follow-up (needs an uploader, per
  `values.yaml`).

## Migrating from the MySQL backend

Migration is **snapshot-based and offline** in v1: one scheduled maintenance
window, no dual-write, no live replication. The vault is a read-through system
with single-writer semantics, so a clean cut is simple and verifiable; live
migration would need a dual-write backend and is not worth its risk here.

1. **Prepare.** Deploy nothing yet. Confirm a recent `operator snapshot save`
   exists (`docs/DEPLOYMENT.md` § Backups) and note the unseal shares / KEK
   location — migration does not change them.
2. **Freeze.** Scale the MySQL-backed release to 0 (clients retry; ESO/PHP
   resolvers already tolerate an outage, D-019). The database is now quiescent.
3. **Export (physical, no unseal needed).** `operator snapshot save -storage
   mysql -storage-mysql-dsn …` reads the ciphertext straight from MySQL. *(New
   subcommand form: today `save` is API-only; the offline variant is a small
   slice because `snapshot.Write` already takes a `Backend`.)* Record the entry
   count and a SHA-256 over the sorted key/value stream.
4. **Import.** On `ubixvault-0`'s fresh PVC:
   `operator snapshot restore -storage raft -data <dir> <file>`; compute the
   same count + hash from the restored `fsm.db` and compare. A mismatch aborts.
5. **Start and unseal `-0`** with the *same* auto-unseal config (or shares).
   Verify: `sys/health`, a known KV read, an auth login, a transit round trip.
6. **Join `-1`, `-2`** (join tokens), wait for both promoted to voter.
7. **Cut clients over** (the Service already points at the StatefulSet).
8. **Soak.** Leave the MySQL database untouched and unreferenced for the soak
   period (dev: ≥ 1 week; prod: ≥ 2 weeks and one full backup cycle).

**Rollback.** Until step 8's soak ends, rollback is: stop the Raft release,
`operator snapshot save` from Raft (carries any writes made since cutover),
`operator snapshot restore -storage mysql` into the database (after
truncating it — destructive, documented, an operator action), redeploy the
`storage.type: mysql` release. The barrier, unseal material and tokens are
identical on both sides because nothing above storage changed, so no secret,
token or lease is invalidated in either direction.

What migration does **not** change: unseal shares / KEK, root and other tokens,
leases, policies, mounts, the API address clients use, and the audit HMAC key
(it is in the barrier).

## Kubernetes deployment

New chart value `storage.type: raft` (alongside `file` and `mysql`).

- **StatefulSet, `replicaCount: 3` (default; 5 optional), odd only.**
  `podManagementPolicy: Parallel` is **not** used: `OrderedReady` makes `-0`
  bootstrap and the rest join in sequence, and rolling updates proceed one pod
  at a time (`-2`→`-0`) behind readiness.
- **A PVC per pod** via `volumeClaimTemplates` (`storage.raft.persistence`:
  `size` default 10Gi, `storageClass`), mounted at the data dir. Block storage
  with honest `fsync` is required — **not** NFS/SMB; bbolt and Raft assume
  POSIX fsync semantics. The existing `persistence` block (file backend) is
  reused/renamed for this; the MySQL `dsnSecret` is not required.
- **Headless Service** (`<fullname>-headless`, `publishNotReadyAddresses:
  true`) giving each pod a stable DNS name for `-raft-advertise-addr` and
  retry-join. This replaces D-021's "no headless Service, pods advertise
  `POD_IP`" for Raft mode only; the main ClusterIP Service is unchanged and
  still selects all pods (standbys forward).
- **Readiness:** `/v1/sys/health?standbyok=true` as in D-021 — a sealed or
  not-yet-joined node is not ready, so a rolling update never takes a second
  voter down before the first is back and caught up.
- **PodDisruptionBudget `maxUnavailable: 1`** and pod anti-affinity (now
  *recommended hard* for 3+ nodes; with soft, two voters on one node defeat the
  point of replication). Added: `terminationGracePeriodSeconds` covers
  leadership transfer + snapshot flush.
- **Secrets:** auto-unseal config (as today) is mandatory in practice —
  without it every restart of every replica waits for an operator. Join token
  and pinned CA arrive via a Secret/initContainer for ordinals > 0.
- **NetworkPolicy:** 8200 as before; 8201 pod-to-pod only (now also carrying
  Raft).
- **Backup CronJob:** unchanged; targets the Service, uses the snapshot API.

### Effect on `ubixvault-dev` / `ubixvault-prod`

Today both instances (`ubixvault` in dev, `ubixvault-prod`) run the chart at
`storage.type: mysql` against an external MySQL outside the cluster (per the
2026-09 storage-outage report, both point at the same server — separate
databases/DSNs per instance must be confirmed before migration, as each
instance is snapshotted and cut over on its own). D-021 rolls HA out to dev at
3 replicas first, then prod.

- **No change to the namespaces themselves:** same names, same Services, same
  Ingress, same `*.ubixsys.com` certificate on 8200; clients are not touched.
- **The MariaDB dependency leaves the vault's critical path** for the
  namespace that migrates; its DSN Secret becomes unused (kept through soak).
- **New per-namespace resources:** 3 PVCs, the headless Service.
- **A new StatefulSet is required.** `volumeClaimTemplates` and `serviceName`
  are immutable on an existing StatefulSet, and the MySQL-mode set has neither
  a data PVC nor a headless service. The migration therefore recreates the
  StatefulSet (`kubectl delete sts --cascade=orphan` then `helm upgrade`, or a
  parallel release name) as part of step 2–4 above. The build lane must
  validate which of the two is cleaner with the existing `helm` release
  history before the dev cutover.
- **Order: dev first, soak, then prod**, each a separate `kubernetes`-repo MR
  gated on its own backup + verification step. The rolling-upgrade and
  enabling-HA procedures in `docs/DEPLOYMENT.md` § Upgrades gain a Raft
  section.

## Failure modes

| Failure | Behaviour | Operator action |
| --- | --- | --- |
| One voter down (3-node) | Quorum holds; leader unaffected, or re-elected in seconds if it was the leader. Writes continue. | Replace/restart; it catches up. |
| Leader pod killed | Election (heartbeat/election timeouts, ~seconds); standbys hold requests up to 5s (D-021 §4), clients retry beyond. | None. |
| Two of three down | **No quorum: writes fail 503**, reads on the survivor may be refused (it steps down), cluster not ready. No data loss. | Restore one voter; or `operator raft recover` as last resort. |
| Network partition | Majority side keeps/elects a leader; minority leader steps down within the lease and its writes fail. Pre-vote prevents term inflation on heal. | None; minority catches up on heal. |
| Paused leader (GC/CPU/VM freeze) | Resumes believing it leads; its next `Apply` fails (new term) ⇒ `ErrFenced`, steps down. A stale read within the lease is possible and bounded. | None. |
| Disk full on a node | bbolt write fails ⇒ FSM fail-stop on that node (never skips an entry); it leaves quorum, is reported unhealthy. Persisting on every node ⇒ cluster read-only/503. | Grow PVC / compact; alert on `ubixvault_raft_disk_*`. |
| Corrupt `fsm.db` / `raft.db` | Detected at open (checksum/bbolt panic caught); node refuses to start. | Wipe PVC and re-join (normal replacement). |
| Slow disk (fsync latency) | Heartbeat misses ⇒ spurious elections / flapping. | Faster storage class; alert on fsync/commit latency; raise timeouts last. |
| Snapshot restore mid-flight crash | Raft snapshot install is atomic via the snapshot store; node reverts to previous state and retries. | None. |
| Cluster CA / leaf expiry while sealed | Leaves are memory-only and reissued on unseal, so nothing expires at rest; the CA has a 10-year life with a rotation runbook. | Rotate at ~year 8. |
| Lost unseal material | Same as every backend: the data is unrecoverable by design. | — |
| Join token leaked | Single-use, 15-minute TTL; usable only until burned. A joined rogue node is removable and holds only ciphertext. | `remove-peer`; rotate cluster CA if its leaf might have been exfiltrated. |
| Version skew in a rolling upgrade | New commands gated until all voters advertise support; old nodes never see an op they cannot apply. | Finish the roll. |

## Future: CAS and transactions

Not in v1 — the `Backend` contract stays four methods, last-writer-wins, and
the single-writer rule of D-021 remains what makes read-modify-write safe.
**But Raft makes both natural and the design reserves the room:**

- The command format is versioned and has a reserved `txn` op from day one.
- Every key can carry its **last-modified Raft index** as a free, strictly
  monotonic version (an extra bbolt value field, written by the FSM).
- A later, optional interface — say `storage.TxnBackend` with
  `Txn(ctx, preconditions, ops)` where preconditions are
  exists/not-exists/version-equals — would be applied *atomically in the FSM*,
  returning a deterministic success/failure to the proposer. The file and MySQL
  backends can implement it too (a mutex; `UPDATE … WHERE version = ?`).
- That is the prerequisite D-021 named for **multi-active serving and
  performance standbys**: each existing read-modify-write (wrapping, transit
  rotate, identity alias creation, lease counts, the sweeper) is converted to
  a conditional write one at a time, with the lock-based single writer
  retained until the last is done. It is the right next design after this one,
  and the `txn` reservation exists so this design does not have to be revisited
  for it.

## Testing

1. **Conformance:** the Raft backend passes `runBackendConformance`
   (`storagetest`) unchanged — the correctness gate for `Get/Put/Delete/List`
   semantics and key-length limits. Plus a *cross-backend* test: snapshot →
   restore across file ⇄ mysql ⇄ raft is lossless (count + hash).
2. **FSM:** determinism (replay the same log twice ⇒ identical bbolt), idempotent
   re-apply after crash at every point of an apply, unknown-version refusal,
   fuzz of command decoding and the offline snapshot restore into raft.
3. **In-process cluster harness** (`internal/storage/raft`; today `cluster_test.go`, a `rafttest` sub-package once fault injection lands): N
   nodes over an in-memory transport with fault injection — drop/delay/reorder,
   asymmetric partition, node pause, crash-restart with intact/wiped disk,
   disk-full on one node, torn write at crash mid-snapshot. Runs in plain
   `go test` (seconds), the fast loop for the Raft slices.
4. **Jepsen-lite:** concurrent clients doing `Put/Get/Delete` on a few keys
   against the harness under random faults; record the history (invoke/ok/fail/
   info) and check **per-key linearizability** with a small in-house register
   checker (single-key registers need no general checker; an off-the-shelf
   checker is a possible later swap). Also checked: no acknowledged write is
   lost across leader changes and restarts; no write is acknowledged by two
   leaders in one term (the `ErrFenced` property); wrapping tokens stay
   single-use across a leader change. Runs as a nightly/longer job, with a
   seed printed on failure for replay.
5. **Chaos on kind** (extends the D-021 `feat/ha-e2e`): kill the leader under
   load, drain nodes, kill two nodes and restore, rolling upgrade, network
   partition via NetworkPolicy, PVC loss + re-join, full-cluster restart with
   auto-unseal; assert the measured gap, zero lost acknowledged writes, and
   that no write lands from a fenced leader.
6. **Migration rehearsal:** the full MySQL → Raft procedure, and rollback,
   run in CI against a seeded dataset (all engines populated), comparing
   engine-level reads before and after.
7. **Security review items** (added to `SECURITY_REVIEW_BRIEF.md` when built):
   peer authentication and the join token, ALPN confusion between forwarding
   and Raft on one listener, snapshot handling (hostile snapshot into
   `restore`, already fuzzed), and `peers.json` recovery as a privileged
   offline path.

## Build plan

Each slice is one MR, in order, and each is safe to merge on its own — nothing
changes at runtime until `-storage raft` is selected (slice 7 turns it into a
supported deployment).

| # | Slice | Contents | Verification |
| --- | --- | --- | --- |
| 0 | This design + ADR D-023 | docs only | review |
| 1 | `raft` skeleton + FSM | package, bbolt FSM, versioned commands, single-node `Backend`, `-storage raft` for one node, dependency added and graph recorded in the ADR | `runBackendConformance`; FSM determinism/idempotence tests; `govulncheck`, licence check |
| 2 | Snapshots | FSM snapshot/restore in v1 NDJSON, raft snapshot store, offline `snapshot restore -storage raft` and offline `snapshot save -storage mysql`, count+hash verify | cross-backend lossless round trips; `FuzzRestore` extended |
| 3 | Multi-node core | in-memory + TLS stream layer, membership APIs internally, in-process cluster harness, fault injection, leader/barrier read rules | harness tests; first Jepsen-lite run (no HA wiring yet) |
| 4 | HA wiring | `raft.Lock` implementing `HABackend` (term = generation), Barrier-on-active, step-down as `LeadershipTransfer`, `-ha` semantics, flags | existing HA/forward tests reused against raft; fencing tests |
| 5 | Cluster transport + join | ALPN-mux on the cluster listener, bridge leaves, join-token flow, non-voter→voter promotion | harness + 3-process local test; join-token abuse tests |
| 6 | Operator API + CLI | `sys/storage/raft/*`, `operator raft …`, `peers.json` recovery, autopilot-state subset, metrics, docs | API tests; compatibility check against Vault CLI shapes |
| 7 | Chart + docs | `storage.type: raft`, headless Service, PVC template, PDB/anti-affinity rules, NetworkPolicy, `DEPLOYMENT.md` Raft + upgrade sections | `helm template`/lint; kind e2e smoke (3 pods, kill leader) |
| 8 | Chaos + migration e2e | kind chaos suite, migration + rollback rehearsal, performance baseline vs MySQL (write/list latency), nightly Jepsen-lite | pass criteria written into the MR; numbers recorded in this note |
| 9 | Release | MINOR (additive), README/POSITIONING/ROADMAP/SECURITY updates; dev rollout then prod via `kubernetes`-repo MRs | per the soak policy above |

Slices 1–3 are the risk: they should land with the in-process harness green
*before* any HA wiring is built on top. Slices 5 and 6 can be reordered or
parallelized once 4 lands.

## Implementation status

First MR (`feat/raft-storage`), package `internal/storage/raft`. The package
is named `raft`, not `raftstore` as drafted above (the lane and import path
settled on the shorter name; D-023 now says `raft`).

**Built:**

- Slice 1: bbolt FSM (`fsm.db`), versioned JSON commands (`txn` reserved and
  refused), single- and multi-node `storage.Backend`, last-applied index in the
  same bbolt transaction (idempotent re-apply), fail-stop on an apply failure
  (the node latches `ErrFailed` and refuses all further entries, reads and
  writes; "seal and report unhealthy" needs core wiring, slice 4).
- Slice 2 (core): FSM snapshot/restore in `ubixvault-snapshot v1` via
  `internal/snapshot`, raft file snapshot store (retain 2), leader-driven
  `RestoreSnapshot` that parses and validates the snapshot *before* proposing it
  (a restore failing inside the library's FSM is fatal to the node), and
  `WriteSnapshot` for a point-in-time export.
- Slice 3 (part): in-memory and plaintext-TCP transports, membership
  (`AddVoter`, `AddNonvoter`, `RemoveServer`, `TransferLeadership`), pre-vote on
  (library default), in-process 3-node tests: replication, follower write
  fencing, leader loss and catch-up on restart, no-quorum writes failing,
  snapshot install on join after compaction, cluster-wide restore, TCP
  transport.
- The shared backend contract suite moved to `storagetest.RunBackendConformance`
  and now runs against memory, file, MySQL (integration tag) and Raft.

- Slice 4 (HA wiring): `raft.Backend` implements `HABackend`. `Acquire` waits for
  leadership, applies a barrier and writes the holder record
  (`core/ha/raft-holder`); `Holder.Generation` is the term (the `Stats()["term"]`
  parse is pinned by a test); `Release` clears the record and calls
  `LeadershipTransfer`, and writes are fenced to the term a handle acquired in.
  A failed state machine closes `lost`, makes `Acquire`/`Holder` return
  `storage.ErrFailed`, and core seals and reports unhealthy (`Core.HAFailed`).
  Two handles on one node (the Initialize handle and the RunHA handle) are both
  granted while the node leads; the holder record names the last writer.

- Slice 5 (transport + join, library side): `NewTLSTransport` is a
  `raft.StreamLayer` over TLS 1.3 with a client certificate required and ALPN
  `ubixvault-raft/1`. Peers are accepted if their leaf chains to the CA from an
  injected `Credentials` (consulted per handshake, so a rotated leaf/CA applies
  to the next connection); there is no hostname check, since leaves carry no
  stable name. Join tokens: `MintJoinToken` (256-bit, only the SHA-256 is
  replicated, default 15 min), `RedeemJoinToken` (verify and burn in one
  committed log entry, so concurrent or cross-failover redemption has one
  winner; `ErrTokenInvalid/Expired/Used`), `JoinNode` (burn then `AddNonvoter`).
  The proposer's clock rides in the command; the FSM reads none. Records live
  under the reserved key prefix `raft-internal/join-token/` (included in
  snapshots, refused by public `Put`/`Delete`), expired ones pruned on the next
  mint. Decision: **a sealed replica does not vote** (person, decision 189).
  Tests: 3-node cluster over mTLS; refused peers (no cert, wrong CA, expired,
  wrong/no ALPN, server outside the CA); token expiry, reuse, tamper, 8-way
  concurrent redeem; join over TLS.

- Slice 6 (in progress, three ordered MRs):
  - **A. Flag, config, wiring (built).** `-storage raft` (`-data`,
    `-raft-node-id`, `-raft-advertise-addr`, `-raft-bootstrap`); `-ha` is
    implied. `cluster.Mux` terminates mutual TLS on the cluster listener and
    dispatches on ALPN (Raft vs. forwarding); `cluster.Certs` is the transport's
    `Credentials` (the CA in the barrier). The transport is built before the
    barrier exists, so its credentials are lazy and refuse every handshake until
    unseal: that is "a sealed replica does not vote" with no transport restart.
    `Certs.IssueBridge` (`raft.LeafIssuer`) mints the 24h leaf, `Certs.SetBridge`
    installs it on a sealed joiner (memory only; a restart before first unseal
    needs a new token), and `Backend.AcceptJoin` issues it *before* burning the
    token. Promotion: the joiner reports its applied index
    (`Backend.ReportApplied`), and `RunPromotion` promotes after it stays within
    16 entries for 10s with fresh reports; the report transport is MR B.
    Metrics `ubixvault_raft_*`. Offline `snapshot restore -storage raft` into an
    empty directory.
  - **B. Operator API and CLI.** `sys/storage/raft/{join,join-token,configuration,
    remove-peer,snapshot,snapshot-force,autopilot/state}`, `operator raft …`, the
    joiner's retry-join and applied-index report loop, persistence of the bridge
    credential.
  - **C. Recovery and CA rotation.** Offline `peers.json` recovery (consumed on
    start) and the cluster-CA rotation procedure.

**Not built (later slices):** the `sys/storage/raft/*` API and CLI, the joiner
report/retry-join loop and `peers.json` recovery (slice 6 MR B/C); cluster-CA
rotation procedure (MR C); chart; fault-injection harness and Jepsen-lite.

**Findings while building**

- **Keys must be valid UTF-8** *(resolved: `storage.ValidateKey` now rejects
  them for every backend, with a conformance case).* Original finding: Keys travel as JSON strings in log entries and in
  the v1 snapshot format, and `encoding/json` silently rewrites invalid UTF-8.
  The Raft backend rejects such keys with `ErrInvalidKey` instead of letting
  them read back different. The file, memory and MySQL backends do not enforce
  this, so a store that held one could not be snapshotted losslessly; barrier
  paths are ASCII in practice. Worth enforcing in `storage.ValidateKey` (a
  one-line change, separate MR) so all backends agree.
- **Snapshot install starves heartbeats on the follower.** A follower processes
  RPCs serially, so an install-snapshot (bbolt rewrite plus fsync) delays its
  heartbeat replies; a leader with a short `LeaderLeaseTimeout` steps down
  mid-restore. Observed at a 50ms lease on a laptop; the in-process tests use
  heartbeat/election 300ms and lease 250ms. The library defaults (500ms lease)
  are the right production floor; slice 8's measurements should confirm it on
  real PVCs, and this is another reason to keep restore cheap.
- **A restore is a whole-state replacement** and buffers the snapshot in memory
  for validation. Fine for the MB-to-low-GB stores in scope; a streaming
  validator is needed if stores grow past available memory.
- **Long snapshot read transactions** hold bbolt free pages and can stall a
  writer that needs to grow the file while one is open; snapshot duration is the
  metric to watch (already listed above).
- **`Holder.Generation = term`:** the library exposes the term only through
  `Stats()`, parsed as a string. Acceptable, but slice 4 should pin it with a
  test against library upgrades.

**Dependency delta (go.mod, direct):** `hashicorp/raft` v1.7.3 (MPL-2.0),
`hashicorp/raft-boltdb/v2` v2.3.1 (MPL-2.0), `go.etcd.io/bbolt` v1.4.3 (MIT),
`hashicorp/go-hclog` v1.6.3 (MIT). **Indirect (new):** `hashicorp/go-metrics`
(MIT), `armon/go-metrics` (MIT), `hashicorp/go-msgpack/v2` (MIT),
`hashicorp/golang-lru` (MPL-2.0), `hashicorp/go-immutable-radix` (MPL-2.0),
`boltdb/bolt` (MIT, pulled by raft-boltdb's v1 migration path),
`fatih/color`, `mattn/go-colorable`, `mattn/go-isatty` (MIT, via hclog),
`golang.org/x/sys`. MPL-2.0 is file-level copyleft: it constrains modified
copies of those files, not this repository; recorded for the licence review.
raft v1.8.0 and raft-boltdb v2.4.2 were not taken because they raise the `go`
directive to 1.26.0; v1.7.3 / v2.3.1 keep it at 1.25.0 (CI and the Dockerfile
are already on 1.26). Upgrading is a one-line follow-up when the directive is
bumped on purpose. `govulncheck` v1.9.0 (DB
2026-10-08, go1.27.2) reports **0 vulnerabilities affecting the code** and none in
`hashicorp/raft`, `raft-boltdb`, bbolt or `go-hclog`. It lists 4 advisories in
required module `golang.org/x/crypto@v0.54.0` (GO-2026-6355, -6354, -6303 fixed
in v0.55/v0.56; GO-2026-5932 has no fix) in code the binary does not call; they
predate and are unrelated to Raft, and a `x/crypto` bump is a separate change.
D-023 is Accepted.

## Open questions

- **Should a sealed replica vote?** This note says no (transport only after
  unseal; fewer at-rest identities, simpler). It means a full restart under
  Shamir needs a quorum of operators' unseals before writes resume. Vault
  differs. **Decided (slice 5): no**; auto-unseal deployments (both ours) are
  unaffected.
- **StatefulSet recreation vs. a parallel release** for the dev/prod cutover
  (see Kubernetes). Needs a dry run against the real Helm history.
- **Log store:** `raft-boltdb/v2` (default here) vs `hashicorp/raft-wal`.
  Decide on slice 8's measurements, not before.
- **Strict reads default:** lease-based local reads (this note) vs
  `VerifyLeader` on every active read. Measure the cost in slice 4; the
  decision-bearing call sites use strict reads either way.
- **Even-sized / 2-node clusters:** refused in the chart; confirm that is
  acceptable for any consumer who runs 2 replicas today under D-021 (they
  should stay on MySQL or move to 3).
