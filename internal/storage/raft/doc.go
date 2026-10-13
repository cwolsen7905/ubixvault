// Package raft is uBixVault's integrated storage: a [storage.Backend] whose
// state is replicated across vault processes with Raft, so a cluster needs no
// external database (docs/design/raft-storage.md, ADR D-023).
//
// The consensus library (github.com/hashicorp/raft) and its log store are
// confined to this package: nothing outside it imports them.
//
// Layout of a node's data directory:
//
//	<dir>/raft/raft.db     Raft log, current term and vote (raft-boltdb)
//	<dir>/raft/snapshots/  Raft snapshot store, newest two retained
//	<dir>/fsm.db           the applied key/value state (bbolt)
//
// Values reaching this package are already barrier ciphertext, so the log, both
// bbolt files and every snapshot hold only ciphertext (docs/DESIGN.md §3.2).
// Keys are plaintext paths, as with every other backend.
//
// Raft snapshots are streamed in the existing "ubixvault-snapshot v1" format of
// internal/snapshot, so one artifact serves compaction, follower catch-up,
// backup and restore.
package raft
