package raft

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	hraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	bolt "go.etcd.io/bbolt"
)

// peersFile is the name, inside the node's raft directory, of the recovery
// file consumed on start.
const peersFile = "peers.json"

// lockProbeTimeout bounds how long [WriteRecovery] waits for the log store's
// file lock before concluding that a server is running on the directory.
const lockProbeTimeout = time.Second

// peerRecord is one entry of peers.json. The shape matches Vault's
// integrated-storage recovery file.
type peerRecord struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	NonVoter bool   `json:"non_voter,omitempty"`
}

// ParsePeers validates the contents of a peers.json file. It must list at
// least one voter, with unique non-empty IDs and addresses.
func ParsePeers(data []byte) ([]Server, error) {
	var recs []peerRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("raft: peers file: %w", err)
	}
	ids := map[string]bool{}
	addrs := map[string]bool{}
	voters := 0
	out := make([]Server, 0, len(recs))
	for _, r := range recs {
		switch {
		case r.ID == "" || r.Address == "":
			return nil, errors.New("raft: peers file: every entry needs an id and an address")
		case ids[r.ID]:
			return nil, fmt.Errorf("raft: peers file: duplicate id %q", r.ID)
		case addrs[r.Address]:
			return nil, fmt.Errorf("raft: peers file: duplicate address %q", r.Address)
		}
		ids[r.ID], addrs[r.Address] = true, true
		if !r.NonVoter {
			voters++
		}
		out = append(out, Server{ID: r.ID, Address: r.Address, Voter: !r.NonVoter})
	}
	if voters == 0 {
		return nil, errors.New("raft: peers file: at least one voter is required")
	}
	return out, nil
}

// WriteRecovery stages a peers.json for the node whose data directory is
// dataDir; the next [Open] on that directory replaces the cluster
// configuration with it and deletes the file. The node must be stopped, and it
// must itself appear in the list.
//
// Recovery can lose writes that were acknowledged only by the members that are
// no longer in the list.
func WriteRecovery(dataDir, nodeID string, peers []Server) error {
	if len(peers) == 0 {
		return errors.New("raft: recovery needs at least one peer")
	}
	raw := make([]peerRecord, 0, len(peers))
	for _, p := range peers {
		raw = append(raw, peerRecord{ID: p.ID, Address: p.Address, NonVoter: !p.Voter})
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("raft: encode peers: %w", err)
	}
	if _, err := ParsePeers(blob); err != nil {
		return err
	}
	self := false
	for _, p := range peers {
		self = self || p.ID == nodeID
	}
	if !self {
		return fmt.Errorf("raft: node %q is not in the peers list", nodeID)
	}

	raftDir := filepath.Join(dataDir, "raft")
	dbPath := filepath.Join(raftDir, "raft.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("raft: %s holds no Raft state to recover: %w", dataDir, err)
	}
	// A running server holds the log store's file lock; refuse rather than
	// rewrite membership under it.
	probe, err := raftboltdb.New(raftboltdb.Options{
		Path:        dbPath,
		BoltOptions: &bolt.Options{Timeout: lockProbeTimeout},
	})
	if err != nil {
		return fmt.Errorf("raft: log store is in use; stop the server first: %w", err)
	}
	if err := probe.Close(); err != nil {
		return fmt.Errorf("raft: close log store: %w", err)
	}

	tmp := filepath.Join(raftDir, peersFile+".tmp")
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("raft: write peers file: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(raftDir, peersFile)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("raft: stage peers file: %w", err)
	}
	return nil
}

// recoverFromFile applies a staged peers.json, if any, as the node's cluster
// configuration, then deletes it so it is applied once. The file is left in
// place if recovery fails, so the failure repeats rather than being skipped.
func recoverFromFile(raftDir string, rc *hraft.Config, f hraft.FSM, logs hraft.LogStore,
	stable hraft.StableStore, snaps hraft.SnapshotStore, tr hraft.Transport,
) error {
	path := filepath.Join(raftDir, peersFile)
	data, err := os.ReadFile(path) //nolint:gosec // G304: fixed name inside the node's own data dir
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("raft: read %s: %w", peersFile, err)
	}
	peers, err := ParsePeers(data)
	if err != nil {
		return err
	}
	conf := hraft.Configuration{}
	self := false
	for _, p := range peers {
		suf := hraft.Voter
		if !p.Voter {
			suf = hraft.Nonvoter
		}
		self = self || p.ID == string(rc.LocalID)
		conf.Servers = append(conf.Servers, hraft.Server{
			Suffrage: suf, ID: hraft.ServerID(p.ID), Address: hraft.ServerAddress(p.Address),
		})
	}
	if !self {
		return fmt.Errorf("raft: %s does not list this node (%s)", peersFile, rc.LocalID)
	}
	if err := hraft.RecoverCluster(rc, releasingFSM{f}, logs, stable, snaps, tr, conf); err != nil {
		return fmt.Errorf("raft: recover: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("raft: consume %s: %w", peersFile, err)
	}
	return nil
}

// releasingFSM lets RecoverCluster use the real state machine. The library
// persists an FSM snapshot but never releases it, which would leave the
// snapshot's read transaction open and block the next write (the restore in
// NewRaft); releasing after Persist is safe because nothing else uses it.
type releasingFSM struct{ hraft.FSM }

func (r releasingFSM) Snapshot() (hraft.FSMSnapshot, error) {
	s, err := r.FSM.Snapshot()
	if err != nil {
		return nil, err
	}
	return releasingSnapshot{s}, nil
}

type releasingSnapshot struct{ hraft.FSMSnapshot }

func (s releasingSnapshot) Persist(sink hraft.SnapshotSink) error {
	defer s.Release()
	return s.FSMSnapshot.Persist(sink)
}
