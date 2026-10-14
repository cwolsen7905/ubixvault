package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

func TestRestoreIntoRaftOffline(t *testing.T) {
	ctx := context.Background()
	src := storage.NewMemoryBackend()
	_ = src.Put(ctx, &storage.Entry{Key: "sys/a", Value: []byte("1")})
	var buf bytes.Buffer
	if err := snapshot.Write(ctx, src, &buf); err != nil {
		t.Fatal(err)
	}

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	r := raftFlags(fs)
	if err := fs.Parse([]string{"-raft-node-id", "n1", "-raft-advertise-addr", "127.0.0.1:18999"}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := restoreIntoRaft(r, dir, &buf); err != nil {
		t.Fatalf("restoreIntoRaft: %v", err)
	}
	// A second restore into the same directory is refused.
	if err := restoreIntoRaft(r, dir, bytes.NewReader(nil)); err == nil {
		t.Fatal("restore into a populated Raft directory was allowed")
	}

	// The directory reopens as the same single-voter node, with the data.
	b, err := raftstore.Open(raftstore.Config{
		NodeID: "n1", DataDir: dir, Transport: raftstore.NewInmemTransport("127.0.0.1:18999"),
		HeartbeatTimeout: 200 * time.Millisecond, ElectionTimeout: 200 * time.Millisecond, LeaderLeaseTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	e, err := b.Get(ctx, "sys/a")
	if err != nil || e == nil || string(e.Value) != "1" {
		t.Fatalf("restored value = %v, %v", e, err)
	}
	srv, _ := b.Configuration()
	if len(srv) != 1 || srv[0].Address != "127.0.0.1:18999" || !srv[0].Voter {
		t.Fatalf("configuration = %+v", srv)
	}
}

func TestRecoverRaftStagesPeers(t *testing.T) {
	dir := t.TempDir()
	b, err := raftstore.Open(raftstore.Config{
		NodeID: "n1", DataDir: dir, Transport: raftstore.NewInmemTransport("127.0.0.1:18998"), Bootstrap: true,
		HeartbeatTimeout: 200 * time.Millisecond, ElectionTimeout: 200 * time.Millisecond, LeaderLeaseTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	r := raftFlags(fs)
	if err := fs.Parse([]string{"-raft-node-id", "n1"}); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`[{"id":"n2","address":"h:1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverRaft(r, dir, bad); err == nil {
		t.Fatal("a list without this node was staged")
	}
	good := filepath.Join(t.TempDir(), "good.json")
	if err := os.WriteFile(good, []byte(`[{"id":"n1","address":"h:1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverRaft(r, dir, good); err != nil {
		t.Fatalf("recoverRaft: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "raft", "peers.json")); err != nil {
		t.Fatalf("peers.json not staged: %v", err)
	}
}
