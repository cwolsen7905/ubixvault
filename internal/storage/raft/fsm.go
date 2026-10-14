package raft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	hraft "github.com/hashicorp/raft"
	"go.etcd.io/bbolt"

	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// ErrFailed is returned by every operation once the node's state machine has
// failed to apply a committed entry. The node must not skip the entry (that
// would fork its state from the cluster); it stops serving and is repaired by
// replacement or restore (docs/design/raft-storage.md "FSM apply failure").
var ErrFailed = errors.New("raft: state machine failed; node must be replaced or restored")

// fsm is the replicated state machine: an ordered key/value bbolt file. It is
// deterministic — no clocks, randomness or I/O besides its own file.
type fsm struct {
	db     *bbolt.DB
	failed atomic.Bool
}

func openFSM(path string) (*fsm, error) {
	db, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("raft: open fsm: %w", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, b := range [][]byte{kvBucket, metaBucket} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("raft: init fsm: %w", err)
	}
	return &fsm{db: db}, nil
}

func (f *fsm) fail(err error) error {
	f.failed.Store(true)
	return fmt.Errorf("%w: %v", ErrFailed, err)
}

// Apply implements [hraft.FSM]. The returned value is the response handed to
// the proposer's future.
func (f *fsm) Apply(l *hraft.Log) any {
	if f.failed.Load() {
		return ErrFailed
	}
	c, err := decodeCommand(l.Data)
	if err != nil {
		return f.fail(err)
	}
	err = f.db.Update(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		// Raft may re-apply from its log after a crash; an index at or below the
		// recorded one is already reflected in kv.
		if v := meta.Get(lastApplied); len(v) == 8 && l.Index <= binary.BigEndian.Uint64(v) {
			return nil
		}
		kv := tx.Bucket(kvBucket)
		switch c.Op {
		case opPut:
			if err := kv.Put([]byte(c.Key), c.Value); err != nil {
				return err
			}
		case opDelete:
			if err := kv.Delete([]byte(c.Key)); err != nil {
				return err
			}
		}
		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], l.Index)
		return meta.Put(lastApplied, idx[:])
	})
	if err != nil {
		return f.fail(err)
	}
	return nil
}

// Snapshot implements [hraft.FSM]. It pins a bbolt read transaction — a
// point-in-time MVCC view — so writes continue while the snapshot streams.
func (f *fsm) Snapshot() (hraft.FSMSnapshot, error) {
	if f.failed.Load() {
		return nil, ErrFailed
	}
	tx, err := f.db.Begin(false)
	if err != nil {
		return nil, err
	}
	return &fsmSnapshot{tx: tx}, nil
}

// Restore implements [hraft.FSM]: it atomically replaces the whole state with
// the snapshot's contents, or leaves it untouched on error.
func (f *fsm) Restore(rc io.ReadCloser) error {
	defer func() { _ = rc.Close() }()
	return f.db.Update(func(tx *bbolt.Tx) error {
		if err := tx.DeleteBucket(kvBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucket(kvBucket); err != nil {
			return err
		}
		// Replayed log entries after the snapshot index must apply.
		if err := tx.Bucket(metaBucket).Delete(lastApplied); err != nil {
			return err
		}
		return snapshot.Restore(context.Background(), txBackend{tx}, rc)
	})
}

func (f *fsm) close() error { return f.db.Close() }

// get, list and write the local state outside Raft.
func (f *fsm) get(key string) (*storage.Entry, error) {
	var e *storage.Entry
	err := f.db.View(func(tx *bbolt.Tx) error { e = kvGet(tx, key); return nil })
	return e, err
}

func (f *fsm) list(prefix string) ([]string, error) {
	var out []string
	err := f.db.View(func(tx *bbolt.Tx) error { out = kvList(tx, prefix); return nil })
	return out, err
}

// writeSnapshot streams a consistent copy of the state to w.
func (f *fsm) writeSnapshot(ctx context.Context, w io.Writer) error {
	return f.db.View(func(tx *bbolt.Tx) error {
		return snapshot.Write(ctx, txBackend{tx}, w)
	})
}

type fsmSnapshot struct{ tx *bbolt.Tx }

// Persist implements [hraft.FSMSnapshot].
func (s *fsmSnapshot) Persist(sink hraft.SnapshotSink) error {
	if err := snapshot.Write(context.Background(), txBackend{s.tx}, sink); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

// Release implements [hraft.FSMSnapshot].
func (s *fsmSnapshot) Release() { _ = s.tx.Rollback() }

// txBackend adapts one bbolt transaction to [storage.Backend] so the shared
// snapshot reader/writer can run against the FSM. Writes require a writable
// transaction.
type txBackend struct{ tx *bbolt.Tx }

func (b txBackend) Get(_ context.Context, key string) (*storage.Entry, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	return kvGet(b.tx, key), nil
}

func (b txBackend) Put(_ context.Context, e *storage.Entry) error {
	if err := checkKey(e.Key); err != nil {
		return err
	}
	return b.tx.Bucket(kvBucket).Put([]byte(e.Key), e.Value)
}

func (b txBackend) Delete(_ context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	return b.tx.Bucket(kvBucket).Delete([]byte(key))
}

func (b txBackend) List(_ context.Context, prefix string) ([]string, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	return kvList(b.tx, prefix), nil
}
