package main

import (
	"bytes"
	"context"
	"flag"
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
