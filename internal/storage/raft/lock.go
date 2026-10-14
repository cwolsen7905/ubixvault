package raft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// holderKey is the replicated record naming the active replica. It sits under
// the barrier's reserved "core/" prefix, so the barrier never exposes it, and
// it is written by the leader before Acquire returns so every replica can find
// the leader's advertise address (docs/design/raft-storage.md).
const holderKey = "core/ha/raft-holder"

// lockPoll is how often a lock handle re-checks leadership and the term.
const lockPoll = 20 * time.Millisecond

// holderRecord is the value stored at holderKey. A record is current only
// while Node is the Raft leader and Term the current term: a deposed leader's
// record is ignored until its successor writes its own.
type holderRecord struct {
	Holder    string `json:"holder"`
	Advertise string `json:"advertise"`
	Node      string `json:"node"`
	Term      uint64 `json:"term"`
}

var (
	_ storage.HABackend = (*Backend)(nil)
	_ storage.Lock      = (*Lock)(nil)
)

// HALock implements [storage.HABackend]. Raft elects the leader itself, so the
// lock's TTL, renew and retry options are ignored and name is not used: a
// cluster has one lock. Once a handle exists, writes through the backend are
// fenced to the term in which a handle acquired the lock.
func (b *Backend) HALock(_, holderID, advertise string, _ storage.LockOptions) storage.Lock {
	b.haMu.Lock()
	b.haTaken = true
	b.haMu.Unlock()
	return &Lock{b: b, holder: holderID, advertise: advertise}
}

// Failed returns [ErrFailed] once the state machine has failed, else nil.
func (b *Backend) Failed() error {
	if b.fsm.failed.Load() {
		return ErrFailed
	}
	return nil
}

// FailedCh is closed when the state machine fails.
func (b *Backend) FailedCh() <-chan struct{} { return b.fsm.failedCh }

// fenceCheck refuses a write unless some lock handle holds the lock for the
// current term on this leader. Without any handle (HA not in use) it allows.
func (b *Backend) fenceCheck() error {
	b.haMu.Lock()
	defer b.haMu.Unlock()
	if !b.haTaken {
		return nil
	}
	if !b.IsLeader() {
		return storage.ErrFenced
	}
	term := b.Term()
	for _, t := range b.held {
		if t == term {
			return nil
		}
	}
	return storage.ErrFenced
}

// Lock is one replica's handle on the cluster's HA lock. Leadership is the
// lock: Acquire waits for it, the term is the generation, and Release hands
// leadership to another voter.
type Lock struct {
	b         *Backend
	holder    string
	advertise string

	mu   sync.Mutex
	term uint64        // term of the current acquisition, 0 if not held
	stop chan struct{} // closed to end the current acquisition's monitor
}

// Acquire blocks until this node is the Raft leader with its state machine
// caught up and the holder record written. lost is closed when leadership is
// lost, the term changes, the state machine fails, or Release is called.
func (l *Lock) Acquire(ctx context.Context) (<-chan struct{}, error) {
	b := l.b
	t := time.NewTicker(lockPoll)
	defer t.Stop()
	for {
		if err := b.Failed(); err != nil {
			return nil, err
		}
		if b.IsLeader() {
			term := b.Term()
			if err := l.claim(ctx, term); err == nil {
				return l.monitor(term), nil
			} else if errors.Is(err, storage.ErrFailed) || ctx.Err() != nil {
				return nil, err
			}
			// Not leader after all, or the term moved on: wait again.
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-b.FailedCh():
		case <-t.C:
		}
	}
}

// claim applies a barrier, then writes the holder record for term.
func (l *Lock) claim(ctx context.Context, term uint64) error {
	b := l.b
	if err := b.Barrier(); err != nil {
		return err
	}
	if !b.IsLeader() || b.Term() != term {
		return storage.ErrFenced
	}
	val, err := json.Marshal(holderRecord{Holder: l.holder, Advertise: l.advertise, Node: b.cfg.NodeID, Term: term})
	if err != nil {
		return err
	}
	if err := b.proposeRaw(ctx, command{Op: opPut, Key: holderKey, Value: val}); err != nil {
		return err
	}
	if !b.IsLeader() || b.Term() != term {
		return storage.ErrFenced
	}
	b.haMu.Lock()
	b.held[l] = term
	b.haMu.Unlock()
	return nil
}

// monitor starts the goroutine that closes the returned channel when this
// acquisition ends.
func (l *Lock) monitor(term uint64) <-chan struct{} {
	lost := make(chan struct{})
	stop := make(chan struct{})
	l.mu.Lock()
	l.term, l.stop = term, stop
	l.mu.Unlock()
	go func() {
		defer close(lost)
		t := time.NewTicker(lockPoll)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-l.b.FailedCh():
				l.drop(term)
				return
			case <-t.C:
				if !l.b.IsLeader() || l.b.Term() != term {
					l.drop(term)
					return
				}
			}
		}
	}()
	return lost
}

// drop forgets the acquisition for term, if it is still the current one.
func (l *Lock) drop(term uint64) {
	l.mu.Lock()
	if l.term == term {
		l.term, l.stop = 0, nil
	}
	l.mu.Unlock()
	l.b.haMu.Lock()
	if l.b.held[l] == term {
		delete(l.b.held, l)
	}
	l.b.haMu.Unlock()
}

// Release gives the lock up: writes through this node are fenced from now on,
// the holder record is cleared, and — if no other handle on this node still
// holds the lock — leadership is transferred to another voter. A single-voter
// cluster has nowhere to transfer to and stays leader, but fenced.
func (l *Lock) Release(ctx context.Context) error {
	l.mu.Lock()
	term, stop := l.term, l.stop
	l.term, l.stop = 0, nil
	l.mu.Unlock()
	if term == 0 {
		return nil
	}
	close(stop)
	b := l.b
	b.haMu.Lock()
	delete(b.held, l)
	others := len(b.held) > 0
	b.haMu.Unlock()

	if !b.IsLeader() || b.Term() != term {
		return nil
	}
	// Clear the record only if it is still ours.
	if cur, err := b.readHolder(); err == nil && cur != nil && cur.Holder == l.holder && cur.Term == term {
		if err := b.proposeRaw(ctx, command{Op: opDelete, Key: holderKey}); err != nil && !errors.Is(err, storage.ErrFenced) {
			return fmt.Errorf("raft: clear holder: %w", err)
		}
	}
	if others {
		return nil
	}
	if err := b.TransferLeadership(); err != nil && !errors.Is(err, storage.ErrFenced) && !singleVoter(b) {
		return fmt.Errorf("raft: step down: %w", err)
	}
	return nil
}

// singleVoter reports whether this node is the cluster's only voter, where a
// leadership transfer has no target and failing is expected.
func singleVoter(b *Backend) bool {
	cfg, err := b.Configuration()
	if err != nil {
		return false
	}
	n := 0
	for _, s := range cfg {
		if s.Voter {
			n++
		}
	}
	return n <= 1
}

// Holder reports the current leader's record, or a zero Holder while there is
// no leader or its record has not been written yet. Generation is the term.
func (l *Lock) Holder(context.Context) (storage.Holder, error) {
	b := l.b
	if err := b.Failed(); err != nil {
		return storage.Holder{}, err
	}
	rec, err := b.readHolder()
	if err != nil || rec == nil {
		return storage.Holder{}, err
	}
	if id, _ := b.Leader(); id == "" || id != rec.Node || rec.Term != b.Term() {
		return storage.Holder{}, nil
	}
	return storage.Holder{ID: rec.Holder, Advertise: rec.Advertise, Generation: rec.Term}, nil
}

// readHolder returns the stored record from this node's state, or nil.
func (b *Backend) readHolder() (*holderRecord, error) {
	e, err := b.fsm.get(holderKey)
	if err != nil || e == nil {
		return nil, err
	}
	var rec holderRecord
	if err := json.Unmarshal(e.Value, &rec); err != nil {
		return nil, nil // unreadable: treat as no holder
	}
	return &rec, nil
}
