package raft

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// testNode is one node of an in-process cluster.
type testNode struct {
	id  string
	cfg Config
	b   *Backend
}

type testCluster struct {
	t     *testing.T
	nodes map[string]*testNode
}

// newCluster starts n nodes over in-memory transports: n1 bootstraps and the
// others are added to it as voters.
func newCluster(t *testing.T, n int, tune func(*Config)) *testCluster {
	t.Helper()
	c := &testCluster{t: t, nodes: map[string]*testNode{}}
	for i := 1; i <= n; i++ {
		c.start(fmt.Sprintf("n%d", i), i == 1, tune)
	}
	leader := c.waitLeader()
	for i := 2; i <= n; i++ {
		id := fmt.Sprintf("n%d", i)
		if err := leader.AddVoter(id, c.nodes[id].cfg.Transport.Addr()); err != nil {
			t.Fatalf("AddVoter %s: %v", id, err)
		}
	}
	return c
}

// start opens a node (fresh data dir) and wires its transport to every peer.
func (c *testCluster) start(id string, bootstrap bool, tune func(*Config)) *testNode {
	c.t.Helper()
	cfg := testConfig(c.t, id, bootstrap, NewInmemTransport(id))
	if tune != nil {
		tune(&cfg)
	}
	return c.open(cfg)
}

func (c *testCluster) open(cfg Config) *testNode {
	c.t.Helper()
	b, err := Open(cfg)
	if err != nil {
		c.t.Fatalf("Open %s: %v", cfg.NodeID, err)
	}
	c.t.Cleanup(func() { _ = b.Close() })
	nd := &testNode{id: cfg.NodeID, cfg: cfg, b: b}
	for _, p := range c.nodes {
		p.cfg.Transport.Connect(cfg.Transport)
		cfg.Transport.Connect(p.cfg.Transport)
	}
	c.nodes[cfg.NodeID] = nd
	return nd
}

// stop shuts a node down, as a crash that keeps its disk.
func (c *testCluster) stop(id string) {
	c.t.Helper()
	if err := c.nodes[id].b.Close(); err != nil {
		c.t.Fatalf("Close %s: %v", id, err)
	}
}

// restart reopens a stopped node on its old data directory.
func (c *testCluster) restart(id string) *testNode {
	c.t.Helper()
	cfg := c.nodes[id].cfg
	cfg.Transport = NewInmemTransport(id)
	cfg.Bootstrap = false
	return c.open(cfg)
}

// waitLeader waits until exactly one live node reports leadership.
func (c *testCluster) waitLeader(except ...string) *Backend {
	c.t.Helper()
	var found *Backend
	eventually(c.t, "a leader", func() bool {
		found = nil
		for id, nd := range c.nodes {
			skip := false
			for _, e := range except {
				skip = skip || e == id
			}
			if skip || nd.b.fsm.db == nil {
				continue
			}
			if nd.b.IsLeader() {
				if found != nil {
					return false
				}
				found = nd.b
			}
		}
		return found != nil
	})
	return found
}

func (c *testCluster) leaderID() string {
	c.t.Helper()
	l := c.waitLeader()
	id, _ := l.Leader()
	return id
}

func put(t *testing.T, b *Backend, k, v string) {
	t.Helper()
	if err := b.Put(context.Background(), &storage.Entry{Key: k, Value: []byte(v)}); err != nil {
		t.Fatalf("Put %q: %v", k, err)
	}
}

func hasValue(b *Backend, k, v string) bool {
	e, err := b.Get(context.Background(), k)
	return err == nil && e != nil && string(e.Value) == v
}

func (c *testCluster) waitValue(id, k, v string) {
	c.t.Helper()
	eventually(c.t, fmt.Sprintf("%s to have %s=%s", id, k, v), func() bool {
		return hasValue(c.nodes[id].b, k, v)
	})
}

func TestClusterReplication(t *testing.T) {
	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	for i := 0; i < 20; i++ {
		put(t, leader, fmt.Sprintf("app/k%02d", i), fmt.Sprintf("v%d", i))
	}
	if err := leader.Delete(context.Background(), "app/k00"); err != nil {
		t.Fatal(err)
	}
	for id, nd := range c.nodes {
		c.waitValue(id, "app/k19", "v19")
		eventually(t, id+" applies the delete", func() bool {
			e, _ := nd.b.Get(context.Background(), "app/k00")
			return e == nil
		})
		keys, err := nd.b.List(context.Background(), "app/")
		if err != nil || len(keys) != 19 {
			t.Fatalf("%s: List = %d keys, %v; want 19", id, len(keys), err)
		}
	}
	servers, err := leader.Configuration()
	if err != nil || len(servers) != 3 {
		t.Fatalf("Configuration = %v, %v", servers, err)
	}
	for _, s := range servers {
		if !s.Voter {
			t.Errorf("%s is not a voter", s.ID)
		}
	}
}

func TestFollowerWriteIsFenced(t *testing.T) {
	c := newCluster(t, 3, nil)
	lid := c.leaderID()
	for id, nd := range c.nodes {
		if id == lid {
			continue
		}
		err := nd.b.Put(context.Background(), &storage.Entry{Key: "k", Value: []byte("v")})
		if !errors.Is(err, storage.ErrFenced) {
			t.Fatalf("follower %s Put: want ErrFenced, got %v", id, err)
		}
	}
}

func TestLeaderLoss(t *testing.T) {
	c := newCluster(t, 3, nil)
	old := c.waitLeader()
	oldID, _ := old.Leader()
	oldTerm := old.Term()
	put(t, old, "before", "1")
	for id := range c.nodes {
		c.waitValue(id, "before", "1")
	}

	c.stop(oldID)
	leader := c.waitLeader(oldID)
	if id, _ := leader.Leader(); id == oldID {
		t.Fatalf("leader did not change from %s", oldID)
	}
	if leader.Term() <= oldTerm {
		t.Fatalf("term did not advance: %d -> %d", oldTerm, leader.Term())
	}
	if !hasValue(leader, "before", "1") {
		t.Fatal("acknowledged write lost across leader change")
	}
	put(t, leader, "after", "2") // quorum of 2 of 3 still commits

	// The old leader restarts from its disk and catches up as a follower.
	rejoined := c.restart(oldID)
	eventually(t, "old leader to catch up", func() bool {
		return hasValue(rejoined.b, "after", "2") && hasValue(rejoined.b, "before", "1")
	})
	if rejoined.b.IsLeader() {
		t.Fatal("restarted old leader claims leadership")
	}
}

func TestNoQuorumNoWrites(t *testing.T) {
	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	lid, _ := leader.Leader()
	put(t, leader, "k", "v")
	for id := range c.nodes {
		if id != lid {
			c.stop(id)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := leader.Put(ctx, &storage.Entry{Key: "k2", Value: []byte("v")})
	if err == nil {
		t.Fatal("write succeeded without a quorum")
	}
}

func TestTransferLeadership(t *testing.T) {
	c := newCluster(t, 3, nil)
	old := c.waitLeader()
	oldID, _ := old.Leader()
	if err := old.TransferLeadership(); err != nil {
		t.Fatalf("TransferLeadership: %v", err)
	}
	eventually(t, "leadership to move", func() bool {
		l := c.waitLeader()
		id, _ := l.Leader()
		return id != oldID
	})
}

// A node that joins after the log has been compacted can only catch up by
// installing a snapshot.
func TestSnapshotInstallOnJoin(t *testing.T) {
	tune := func(cfg *Config) {
		cfg.SnapshotThreshold = 20
		cfg.TrailingLogs = 5
		cfg.SnapshotInterval = 20 * time.Millisecond
	}
	c := newCluster(t, 3, tune)
	leader := c.waitLeader()
	const n = 120
	for i := 0; i < n; i++ {
		put(t, leader, fmt.Sprintf("data/%03d", i), fmt.Sprintf("v%d", i))
	}
	if err := leader.Snapshot(); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	joiner := c.start("n4", false, tune)
	if err := leader.AddVoter("n4", joiner.cfg.Transport.Addr()); err != nil {
		t.Fatalf("AddVoter: %v", err)
	}
	c.waitValue("n4", fmt.Sprintf("data/%03d", n-1), fmt.Sprintf("v%d", n-1))
	keys, err := joiner.b.List(context.Background(), "data/")
	if err != nil || len(keys) != n {
		t.Fatalf("joiner has %d keys, %v; want %d", len(keys), err, n)
	}
	// And it replicates live writes after the install.
	put(t, leader, "live", "yes")
	c.waitValue("n4", "live", "yes")
}

// A snapshot taken from one cluster, restored on another's leader, is installed
// on every member and replaces the previous state.
func TestClusterRestore(t *testing.T) {
	ctx := context.Background()
	src := openSingle(t, testConfig(t, "src", true, NewInmemTransport("src")))
	put(t, src, "restored/a", "A")
	put(t, src, "restored/b", "B")
	var buf bytes.Buffer
	if err := src.WriteSnapshot(ctx, &buf); err != nil {
		t.Fatal(err)
	}

	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	put(t, leader, "old/key", "old")
	for id := range c.nodes {
		c.waitValue(id, "old/key", "old")
	}
	if err := leader.RestoreSnapshot(ctx, &buf); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	for id, nd := range c.nodes {
		c.waitValue(id, "restored/b", "B")
		if e, _ := nd.b.Get(ctx, "old/key"); e != nil {
			t.Errorf("%s still has pre-restore key", id)
		}
	}
	put(t, c.waitLeader(), "post", "restore")
	for id := range c.nodes {
		c.waitValue(id, "post", "restore")
	}
	// Membership survived the restore.
	if s, err := c.waitLeader().Configuration(); err != nil || len(s) != 3 {
		t.Fatalf("Configuration after restore = %v, %v", s, err)
	}
}

func TestMembershipRemove(t *testing.T) {
	c := newCluster(t, 3, nil)
	leader := c.waitLeader()
	lid, _ := leader.Leader()
	var victim string
	for id := range c.nodes {
		if id != lid {
			victim = id
		}
	}
	if err := leader.RemoveServer(victim); err != nil {
		t.Fatalf("RemoveServer: %v", err)
	}
	s, err := leader.Configuration()
	if err != nil || len(s) != 2 {
		t.Fatalf("Configuration = %v, %v", s, err)
	}
	put(t, leader, "k", "v") // still commits with the remaining two
}

func TestTCPTransportCluster(t *testing.T) {
	mk := func(id string, boot bool) *Backend {
		tr, err := NewTCPTransport("127.0.0.1:0", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Open(testConfig(t, id, boot, tr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.Close() })
		return b
	}
	a, b := mk("a", true), mk("b", false)
	if err := a.WaitForLeader(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if err := a.AddVoter("b", b.cfg.Transport.Addr()); err != nil {
		t.Fatalf("AddVoter: %v", err)
	}
	put(t, a, "over/tcp", "ok")
	eventually(t, "tcp replication", func() bool { return hasValue(b, "over/tcp", "ok") })
}
