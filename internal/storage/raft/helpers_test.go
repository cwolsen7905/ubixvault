package raft

import (
	"context"
	"testing"
	"time"
)

const testTimeout = 10 * time.Second

func testConfig(t *testing.T, id string, bootstrap bool, tr *Transport) Config {
	t.Helper()
	return Config{
		NodeID:    id,
		DataDir:   t.TempDir(),
		Transport: tr,
		Bootstrap: bootstrap,
		// Generous enough that a snapshot install (which holds a follower's
		// RPC loop through bbolt and fsync) cannot expire the leader's lease.
		HeartbeatTimeout:   300 * time.Millisecond,
		ElectionTimeout:    300 * time.Millisecond,
		LeaderLeaseTimeout: 250 * time.Millisecond,
		CommitTimeout:      5 * time.Millisecond,
		SnapshotInterval:   50 * time.Millisecond,
		SnapshotThreshold:  8192,
		ApplyTimeout:       3 * time.Second,
	}
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// eventually polls cond until it holds or the test times out.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
