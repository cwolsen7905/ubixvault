package raft

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

func (c *testCluster) lock(id string) storage.Lock {
	return c.nodes[id].b.HALock("active", "holder-"+id, "https://"+id+":8200", storage.LockOptions{})
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// TestTermIsParsedFromStats pins the one fragile spot of "term = generation":
// the term is read from the library's Stats() map, whose "term" value is a
// decimal string. A library change that renames or reformats it must fail
// here, not turn every generation into 0.
func TestTermIsParsedFromStats(t *testing.T) {
	c := newCluster(t, 1, nil)
	b := c.waitLeader()
	raw, ok := b.r.Stats()["term"]
	if !ok {
		t.Fatal(`Stats() has no "term" key`)
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n == 0 {
		t.Fatalf(`Stats()["term"] = %q, want a positive decimal`, raw)
	}
	if got := b.Term(); got != n {
		t.Fatalf("Term() = %d, want %d", got, n)
	}
}

func TestLockAcquireAndHolderOnEveryNode(t *testing.T) {
	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	lid, _ := leader.Leader()
	l := c.lock(lid)
	lost, err := l.Acquire(ctxT(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if closed(lost) {
		t.Fatal("lost closed right after Acquire")
	}
	term := leader.Term()
	for id, nd := range c.nodes {
		id, nd := id, nd
		eventually(t, id+" to see the holder", func() bool {
			h, err := nd.b.HALock("active", "x", "", storage.LockOptions{}).Holder(context.Background())
			return err == nil && h.ID == "holder-"+lid && h.Advertise == "https://"+lid+":8200" && h.Generation == term
		})
	}
}

func TestLockReleaseHandsOffAndFencesWrites(t *testing.T) {
	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	lid, _ := leader.Leader()
	l := c.lock(lid)
	lost, err := l.Acquire(ctxT(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	gen1 := leader.Term()
	put(t, leader, "k", "1")

	if err := l.Release(ctxT(t)); err != nil {
		t.Fatalf("Release: %v", err)
	}
	eventually(t, "lost to close", func() bool { return closed(lost) })
	err = leader.Put(context.Background(), &storage.Entry{Key: "k", Value: []byte("2")})
	if !errors.Is(err, storage.ErrFenced) {
		t.Fatalf("write after Release = %v, want ErrFenced", err)
	}

	next := c.waitLeader(lid)
	nid, _ := next.Leader()
	if nid == lid {
		t.Fatal("leadership did not move")
	}
	l2 := c.lock(nid)
	if _, err := l2.Acquire(ctxT(t)); err != nil {
		t.Fatalf("Acquire on new leader: %v", err)
	}
	h, err := l2.Holder(context.Background())
	if err != nil || h.ID != "holder-"+nid || h.Generation <= gen1 {
		t.Fatalf("Holder = %+v, %v; want holder-%s with generation > %d", h, err, nid, gen1)
	}
	put(t, next, "k", "3")
}

func TestLockSingleNodeReleaseFencesButStaysUp(t *testing.T) {
	c := newCluster(t, 1, nil)
	b := c.waitLeader()
	l := c.lock("n1")
	if _, err := l.Acquire(ctxT(t)); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	put(t, b, "a", "1")
	if err := l.Release(ctxT(t)); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if h, err := l.Holder(context.Background()); err != nil || h.ID != "" {
		t.Fatalf("Holder after Release = %+v, %v; want none", h, err)
	}
	if err := b.Put(context.Background(), &storage.Entry{Key: "a", Value: []byte("2")}); !errors.Is(err, storage.ErrFenced) {
		t.Fatalf("write after Release = %v, want ErrFenced", err)
	}
	// Re-acquiring works: a solo replica is its own successor.
	if _, err := l.Acquire(ctxT(t)); err != nil {
		t.Fatalf("re-Acquire: %v", err)
	}
	put(t, b, "a", "3")
}

func TestLockLostOnLeaderLoss(t *testing.T) {
	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	lid, _ := leader.Leader()
	lost, err := c.lock(lid).Acquire(ctxT(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	c.stop(lid)
	eventually(t, "lost to close", func() bool { return closed(lost) })
}

func TestLockReportsFailedBackend(t *testing.T) {
	c := newCluster(t, 1, nil)
	b := c.waitLeader()
	l := c.lock("n1")
	lost, err := l.Acquire(ctxT(t))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	// An entry the FSM cannot decode fails the state machine.
	_ = b.r.Apply([]byte("not json"), time.Second).Error()
	eventually(t, "lost to close", func() bool { return closed(lost) })
	if _, err := l.Acquire(ctxT(t)); !errors.Is(err, storage.ErrFailed) || !errors.Is(err, ErrFailed) {
		t.Fatalf("Acquire = %v, want ErrFailed", err)
	}
	if _, err := l.Holder(context.Background()); !errors.Is(err, storage.ErrFailed) {
		t.Fatalf("Holder = %v, want ErrFailed", err)
	}
}
