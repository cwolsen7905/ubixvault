package raft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	hraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

const defaultApplyTimeout = 10 * time.Second

// Config configures one node's [Backend].
type Config struct {
	// NodeID identifies this node in the cluster; it must be stable across
	// restarts (the pod name, in Kubernetes). Required.
	NodeID string
	// DataDir holds raft/raft.db, raft/snapshots and fsm.db. Required.
	DataDir string
	// Transport carries Raft RPCs to peers. Required.
	Transport *Transport

	// Bootstrap makes a node with no prior state start as a single-voter
	// cluster of itself. Exactly one node of a new cluster is bootstrapped; the
	// others are added to it with [Backend.AddVoter] / [Backend.AddNonvoter]. A
	// node that already has state never bootstraps, so restarting with this set
	// is harmless.
	Bootstrap bool

	// Timeouts and compaction. Zero values take the consensus library's defaults.
	HeartbeatTimeout   time.Duration
	ElectionTimeout    time.Duration
	LeaderLeaseTimeout time.Duration
	CommitTimeout      time.Duration
	SnapshotThreshold  uint64
	SnapshotInterval   time.Duration
	TrailingLogs       uint64

	// ApplyTimeout bounds how long a write waits to be committed. Default 10s.
	ApplyTimeout time.Duration

	// LogOutput receives the consensus library's log lines. Default: discard.
	LogOutput io.Writer
}

// Backend is a Raft-replicated [storage.Backend]. Writes go through the log and
// succeed only on the leader once a quorum has them; reads are served from the
// node's local state machine.
type Backend struct {
	cfg   Config
	r     *hraft.Raft
	fsm   *fsm
	log   *raftboltdb.BoltStore
	apply time.Duration

	haMu    sync.Mutex
	haTaken bool             // an HA lock handle exists; writes are fenced
	held    map[*Lock]uint64 // handles holding the lock, with their term
}

var _ storage.Backend = (*Backend)(nil)

func newLogger(name string, out io.Writer) hclog.Logger {
	if out == nil {
		out = io.Discard
	}
	return hclog.New(&hclog.LoggerOptions{Name: name, Output: out, Level: hclog.Warn})
}

// Open starts a node. It returns once the node is running, not once a leader
// exists; use [Backend.WaitForLeader] to wait for one.
func Open(cfg Config) (*Backend, error) {
	if cfg.NodeID == "" || cfg.DataDir == "" || cfg.Transport == nil {
		return nil, errors.New("raft: NodeID, DataDir and Transport are required")
	}
	raftDir := filepath.Join(cfg.DataDir, "raft")
	if err := os.MkdirAll(filepath.Join(raftDir, "snapshots"), 0o700); err != nil {
		return nil, fmt.Errorf("raft: create data dir: %w", err)
	}

	f, err := openFSM(filepath.Join(cfg.DataDir, "fsm.db"))
	if err != nil {
		return nil, err
	}
	logStore, err := raftboltdb.NewBoltStore(filepath.Join(raftDir, "raft.db"))
	if err != nil {
		_ = f.close()
		return nil, fmt.Errorf("raft: open log store: %w", err)
	}
	lg := newLogger("raft", cfg.LogOutput)
	snaps, err := hraft.NewFileSnapshotStoreWithLogger(raftDir, 2, lg)
	if err != nil {
		_ = logStore.Close()
		_ = f.close()
		return nil, fmt.Errorf("raft: open snapshot store: %w", err)
	}

	rc := hraft.DefaultConfig()
	rc.LocalID = hraft.ServerID(cfg.NodeID)
	rc.Logger = lg
	setDur := func(dst *time.Duration, v time.Duration) {
		if v > 0 {
			*dst = v
		}
	}
	setDur(&rc.HeartbeatTimeout, cfg.HeartbeatTimeout)
	setDur(&rc.ElectionTimeout, cfg.ElectionTimeout)
	setDur(&rc.LeaderLeaseTimeout, cfg.LeaderLeaseTimeout)
	setDur(&rc.CommitTimeout, cfg.CommitTimeout)
	setDur(&rc.SnapshotInterval, cfg.SnapshotInterval)
	if cfg.SnapshotThreshold > 0 {
		rc.SnapshotThreshold = cfg.SnapshotThreshold
	}
	if cfg.TrailingLogs > 0 {
		rc.TrailingLogs = cfg.TrailingLogs
	}

	closeAll := func() {
		_ = logStore.Close()
		_ = f.close()
	}
	if cfg.Bootstrap {
		has, err := hraft.HasExistingState(logStore, logStore, snaps)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("raft: check existing state: %w", err)
		}
		if !has {
			boot := hraft.Configuration{Servers: []hraft.Server{{
				Suffrage: hraft.Voter, ID: rc.LocalID, Address: cfg.Transport.addr,
			}}}
			if err := hraft.BootstrapCluster(rc, logStore, logStore, snaps, cfg.Transport.t, boot); err != nil {
				closeAll()
				return nil, fmt.Errorf("raft: bootstrap: %w", err)
			}
		}
	}

	r, err := hraft.NewRaft(rc, f, logStore, logStore, snaps, cfg.Transport.t)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("raft: start: %w", err)
	}
	apply := cfg.ApplyTimeout
	if apply <= 0 {
		apply = defaultApplyTimeout
	}
	return &Backend{cfg: cfg, r: r, fsm: f, log: logStore, apply: apply, held: map[*Lock]uint64{}}, nil
}

// Close shuts the node down and releases its files.
func (b *Backend) Close() error {
	err := b.r.Shutdown().Error()
	return errors.Join(err, b.log.Close(), b.fsm.close())
}

// Get implements [storage.Backend]. It reads this node's local state, which on
// a follower is a consistent but possibly stale prefix of the log; use
// [Backend.ConsistentGet] where staleness matters.
func (b *Backend) Get(_ context.Context, key string) (*storage.Entry, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if b.fsm.failed.Load() {
		return nil, ErrFailed
	}
	return b.fsm.get(key)
}

// ConsistentGet is Get after confirming this node is still the leader with a
// quorum round trip, so the read reflects every committed write.
func (b *Backend) ConsistentGet(ctx context.Context, key string) (*storage.Entry, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if err := b.r.VerifyLeader().Error(); err != nil {
		return nil, mapErr(err)
	}
	return b.Get(ctx, key)
}

// Put implements [storage.Backend]. It returns once the write is committed by a
// quorum and applied locally. A node that is not the leader returns an error
// wrapping [storage.ErrFenced].
func (b *Backend) Put(ctx context.Context, e *storage.Entry) error {
	if e == nil {
		return storage.ErrInvalidKey
	}
	if err := checkKey(e.Key); err != nil {
		return err
	}
	if strings.HasPrefix(e.Key, tokenPrefix) {
		return storage.ErrInvalidKey
	}
	return b.propose(ctx, command{Op: opPut, Key: e.Key, Value: e.Value})
}

// Delete implements [storage.Backend].
func (b *Backend) Delete(ctx context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if strings.HasPrefix(key, tokenPrefix) {
		return storage.ErrInvalidKey
	}
	return b.propose(ctx, command{Op: opDelete, Key: key})
}

// List implements [storage.Backend], reading local state like [Backend.Get].
func (b *Backend) List(_ context.Context, prefix string) ([]string, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	if b.fsm.failed.Load() {
		return nil, ErrFailed
	}
	return b.fsm.list(prefix)
}

// propose commits c through the log, fenced by the HA lock once one is in use.
func (b *Backend) propose(ctx context.Context, c command) error {
	if err := b.fenceCheck(); err != nil {
		return err
	}
	return b.proposeRaw(ctx, c)
}

// proposeRaw commits c without the HA fence; the lock's own record uses it.
func (b *Backend) proposeRaw(ctx context.Context, c command) error {
	if b.fsm.failed.Load() {
		return ErrFailed
	}
	data, err := c.encode()
	if err != nil {
		return err
	}
	f := b.r.Apply(data, b.apply)
	done := make(chan error, 1)
	go func() {
		if err := f.Error(); err != nil {
			done <- mapErr(err)
			return
		}
		if err, ok := f.Response().(error); ok {
			done <- err
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// mapErr turns "this node cannot commit because it is not (or is no longer) the
// leader" into [storage.ErrFenced], the permanent-for-this-handle signal.
func mapErr(err error) error {
	switch {
	case errors.Is(err, hraft.ErrNotLeader),
		errors.Is(err, hraft.ErrLeadershipLost),
		errors.Is(err, hraft.ErrLeadershipTransferInProgress),
		errors.Is(err, hraft.ErrAbortedByRestore):
		return fmt.Errorf("%w: %v", storage.ErrFenced, err)
	}
	return err
}

// IsLeader reports whether this node currently believes it is the leader.
func (b *Backend) IsLeader() bool { return b.r.State() == hraft.Leader }

// LeaderCh delivers true when this node becomes leader and false when it stops.
func (b *Backend) LeaderCh() <-chan bool { return b.r.LeaderCh() }

// Term returns the node's current Raft term, which only increases. It is the
// fencing generation the HA wiring will report.
func (b *Backend) Term() uint64 {
	n, _ := strconv.ParseUint(b.r.Stats()["term"], 10, 64)
	return n
}

// Leader returns the current leader's node ID and address, or empty strings if
// there is none known.
func (b *Backend) Leader() (id, addr string) {
	a, i := b.r.LeaderWithID()
	return string(i), string(a)
}

// WaitForLeader blocks until some leader is known or ctx ends.
func (b *Backend) WaitForLeader(ctx context.Context) error {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		if _, addr := b.Leader(); addr != "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Barrier blocks until every entry committed before the call is applied to the
// local state machine. A new leader calls it before serving reads.
func (b *Backend) Barrier() error { return mapErr(b.r.Barrier(b.apply).Error()) }

// Server is one member of the cluster configuration.
type Server struct {
	ID      string
	Address string
	Voter   bool
}

// Configuration returns the cluster's current membership.
func (b *Backend) Configuration() ([]Server, error) {
	f := b.r.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	var out []Server
	for _, s := range f.Configuration().Servers {
		out = append(out, Server{ID: string(s.ID), Address: string(s.Address), Voter: s.Suffrage == hraft.Voter})
	}
	return out, nil
}

// AddVoter adds (or promotes) a node as a voting member. Leader only.
func (b *Backend) AddVoter(id, addr string) error {
	return mapErr(b.r.AddVoter(hraft.ServerID(id), hraft.ServerAddress(addr), 0, b.apply).Error())
}

// AddNonvoter adds a node that replicates without voting. Leader only.
func (b *Backend) AddNonvoter(id, addr string) error {
	return mapErr(b.r.AddNonvoter(hraft.ServerID(id), hraft.ServerAddress(addr), 0, b.apply).Error())
}

// RemoveServer removes a node from the configuration. Leader only.
func (b *Backend) RemoveServer(id string) error {
	return mapErr(b.r.RemoveServer(hraft.ServerID(id), 0, b.apply).Error())
}

// TransferLeadership hands leadership to the most caught-up voter. Leader only.
func (b *Backend) TransferLeadership() error {
	return mapErr(b.r.LeadershipTransfer().Error())
}

// Snapshot forces a Raft snapshot (log compaction) now.
func (b *Backend) Snapshot() error { return b.r.Snapshot().Error() }

// WriteSnapshot streams a consistent point-in-time copy of this node's state to
// w in the "ubixvault-snapshot v1" format, without pausing writes.
func (b *Backend) WriteSnapshot(ctx context.Context, w io.Writer) error {
	if b.fsm.failed.Load() {
		return ErrFailed
	}
	return b.fsm.writeSnapshot(ctx, w)
}

// RestoreSnapshot replaces the cluster's state with the snapshot in r and has
// every follower install it; membership is kept. Leader only.
//
// The snapshot is fully parsed and validated before it is proposed, because a
// state machine that fails mid-restore takes the node down.
func (b *Backend) RestoreSnapshot(ctx context.Context, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("raft: read snapshot: %w", err)
	}
	scratch := storage.NewMemoryBackend()
	if err := snapshot.Restore(ctx, scratch, bytes.NewReader(data)); err != nil {
		return err
	}
	err = storage.Walk(ctx, scratch, func(e *storage.Entry) error { return checkKey(e.Key) })
	if err != nil {
		return err
	}
	meta := &hraft.SnapshotMeta{Version: hraft.SnapshotVersionMax, Size: int64(len(data))}
	return mapErr(b.r.Restore(meta, bytes.NewReader(data), b.apply))
}
