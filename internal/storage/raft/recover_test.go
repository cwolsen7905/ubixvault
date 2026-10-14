package raft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

func TestParsePeers(t *testing.T) {
	ok := `[{"id":"a","address":"a:1"},{"id":"b","address":"b:1","non_voter":true}]`
	got, err := ParsePeers([]byte(ok))
	if err != nil || len(got) != 2 || !got[0].Voter || got[1].Voter {
		t.Fatalf("ParsePeers = %+v, %v", got, err)
	}
	for name, in := range map[string]string{
		"malformed":    `{`,
		"empty":        `[]`,
		"no voter":     `[{"id":"a","address":"a:1","non_voter":true}]`,
		"missing addr": `[{"id":"a"}]`,
		"dup id":       `[{"id":"a","address":"a:1"},{"id":"a","address":"a:2"}]`,
		"dup address":  `[{"id":"a","address":"a:1"},{"id":"b","address":"a:1"}]`,
	} {
		if _, err := ParsePeers([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRecoveryRewritesConfigurationOnce(t *testing.T) {
	ctx := ctxT(t)
	cfg := testConfig(t, "n1", true, NewInmemTransport("old:1"))
	b, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, &storage.Entry{Key: "sys/a", Value: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	// Refused: this node is not in the list.
	if err := WriteRecovery(cfg.DataDir, "n1", []Server{{ID: "x", Address: "x:1", Voter: true}}); err == nil {
		t.Fatal("recovery without this node was staged")
	}
	if err := WriteRecovery(cfg.DataDir, "n1", []Server{{ID: "n1", Address: "new:1", Voter: true}}); err != nil {
		t.Fatalf("WriteRecovery: %v", err)
	}

	cfg.Transport = NewInmemTransport("new:1")
	cfg.Bootstrap = false
	b, err = Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	srv, err := b.Configuration()
	if err != nil || len(srv) != 1 || srv[0].Address != "new:1" {
		t.Fatalf("configuration = %+v, %v", srv, err)
	}
	if e, err := b.Get(ctx, "sys/a"); err != nil || e == nil || string(e.Value) != "1" {
		t.Fatalf("data after recovery = %v, %v", e, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "raft", peersFile)); !os.IsNotExist(err) {
		t.Fatalf("peers file not consumed: %v", err)
	}
}

func TestRecoveryBadFileFailsOpenAndStays(t *testing.T) {
	cfg := testConfig(t, "n1", true, NewInmemTransport("a:1"))
	b, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataDir, "raft", peersFile)
	if err := os.WriteFile(path, []byte(`[{"id":"n2","address":"b:1"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Transport = NewInmemTransport("a:1")
	if _, err := Open(cfg); err == nil || !strings.Contains(err.Error(), "does not list this node") {
		t.Fatalf("Open = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed recovery removed the file: %v", err)
	}
}

func TestWriteRecoveryRefusesRunningNode(t *testing.T) {
	ctx := ctxT(t)
	cfg := testConfig(t, "n1", true, NewInmemTransport("a:1"))
	b, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if err := b.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecovery(cfg.DataDir, "n1", []Server{{ID: "n1", Address: "a:1", Voter: true}}); err == nil {
		t.Fatal("recovery staged under a running node")
	}
}
