package raft

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/storage"
	"github.com/cwolsen7905/ubixvault/internal/storage/storagetest"
)

func openSingle(t *testing.T, cfg Config) *Backend {
	t.Helper()
	b, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.WaitForLeader(ctxT(t)); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	return b
}

func TestBackendConformance(t *testing.T) {
	storagetest.RunBackendConformance(t, func(t *testing.T) storage.Backend {
		return openSingle(t, testConfig(t, "n1", true, NewInmemTransport("n1")))
	})
}

func TestRejectsOverlongKey(t *testing.T) {
	b := openSingle(t, testConfig(t, "n1", true, NewInmemTransport("n1")))
	ctx := context.Background()
	long := strings.Repeat("k", maxKeyLen+1)
	if err := b.Put(ctx, &storage.Entry{Key: long, Value: []byte("v")}); !errors.Is(err, storage.ErrInvalidKey) {
		t.Fatalf("Put overlong key: want ErrInvalidKey, got %v", err)
	}
	ok := strings.Repeat("k", maxKeyLen)
	if err := b.Put(ctx, &storage.Entry{Key: ok, Value: []byte("v")}); err != nil {
		t.Fatalf("Put max-length key: %v", err)
	}
}

func TestBinaryKeysAndValues(t *testing.T) {
	b := openSingle(t, testConfig(t, "n1", true, NewInmemTransport("n1")))
	ctx := context.Background()
	val := []byte{0, 1, 2, 0xff, 0xfe, '\n', 0}
	if err := b.Put(ctx, &storage.Entry{Key: "bin/\x00\u00ff", Value: val}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(ctx, "bin/\x00\u00ff")
	if err != nil || got == nil || !bytes.Equal(got.Value, val) {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	// Invalid UTF-8 would not survive the JSON log/snapshot encoding.
	if err := b.Put(ctx, &storage.Entry{Key: "bad/\xff", Value: val}); !errors.Is(err, storage.ErrInvalidKey) {
		t.Fatalf("Put non-UTF-8 key: want ErrInvalidKey, got %v", err)
	}
}

// A restarted node comes back with its data and does not re-bootstrap.
func TestPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t, "n1", true, NewInmemTransport("n1"))
	b, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WaitForLeader(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, &storage.Entry{Key: "a/b", Value: []byte("1")}); err != nil {
		t.Fatal(err)
	}
	termBefore := b.Term()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cfg.Transport = NewInmemTransport("n1")
	b2 := openSingle(t, cfg) // Bootstrap still true: must be ignored
	got, err := b2.Get(ctx, "a/b")
	if err != nil || got == nil || string(got.Value) != "1" {
		t.Fatalf("after restart Get = %+v, %v", got, err)
	}
	if b2.Term() < termBefore {
		t.Fatalf("term went backwards: %d -> %d", termBefore, b2.Term())
	}
	servers, err := b2.Configuration()
	if err != nil || len(servers) != 1 {
		t.Fatalf("Configuration = %v, %v", servers, err)
	}
}

func TestWriteSnapshotRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := openSingle(t, testConfig(t, "n1", true, NewInmemTransport("n1")))
	for _, k := range []string{"a", "b/c", "b/d", "e/f/g"} {
		if err := src.Put(ctx, &storage.Entry{Key: k, Value: []byte("v-" + k)}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := src.WriteSnapshot(ctx, &buf); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	dst := openSingle(t, testConfig(t, "n2", true, NewInmemTransport("n2")))
	if err := dst.Put(ctx, &storage.Entry{Key: "stale", Value: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := dst.RestoreSnapshot(ctx, &buf); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if got, _ := dst.Get(ctx, "stale"); got != nil {
		t.Fatalf("restore did not replace state: stale key survived")
	}
	for _, k := range []string{"a", "b/c", "b/d", "e/f/g"} {
		got, err := dst.Get(ctx, k)
		if err != nil || got == nil || string(got.Value) != "v-"+k {
			t.Fatalf("Get(%q) = %+v, %v", k, got, err)
		}
	}
	// And the node keeps working afterwards.
	if err := dst.Put(ctx, &storage.Entry{Key: "after", Value: []byte("ok")}); err != nil {
		t.Fatalf("Put after restore: %v", err)
	}
}

func TestRestoreRejectsBadSnapshot(t *testing.T) {
	ctx := context.Background()
	b := openSingle(t, testConfig(t, "n1", true, NewInmemTransport("n1")))
	if err := b.Put(ctx, &storage.Entry{Key: "keep", Value: []byte("me")}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"not-a-snapshot": "garbage\n",
		"bad-key":        "ubixvault-snapshot v1\n{\"key\":\"a//b\",\"value\":\"AA==\"}\n",
		"truncated":      "ubixvault-snapshot v1\n{\"key\":\"a\",\"val",
	}
	for name, in := range cases {
		if err := b.RestoreSnapshot(ctx, strings.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if got, _ := b.Get(ctx, "keep"); got == nil {
		t.Fatal("rejected restore damaged existing state")
	}
}
