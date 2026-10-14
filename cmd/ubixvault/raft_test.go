package main

import (
	"bytes"
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestRetryAddrsSkipsSelf(t *testing.T) {
	const list = "https://vault-0.vault-headless.ns.svc:8200, https://vault-1.vault-headless.ns.svc:8200"
	cases := []struct {
		name, node, join string
		want             []string
	}{
		{"first node sees only itself", "vault-0", "https://vault-0.vault-headless.ns.svc:8200", nil},
		{"other node joins the first", "vault-2", list, []string{"https://vault-0.vault-headless.ns.svc:8200", "https://vault-1.vault-headless.ns.svc:8200"}},
		{"self is dropped from a mixed list", "vault-1", list, []string{"https://vault-0.vault-headless.ns.svc:8200"}},
		{"bare host and port", "vault-0", "vault-0:8200", nil},
		{"prefix of another name is not self", "vault", "https://vault-0.x:8200", []string{"https://vault-0.x:8200"}},
		{"unset", "vault-0", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			r := raftFlags(fs)
			if err := fs.Parse([]string{"-raft-node-id", c.node, "-raft-retry-join", c.join}); err != nil {
				t.Fatal(err)
			}
			got := r.retryAddrs()
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func guardOpts(t *testing.T, args ...string) *raftOpts {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	r := raftFlags(fs)
	if err := fs.Parse(append([]string{"-raft-node-id", "vault-0"}, args...)); err != nil {
		t.Fatal(err)
	}
	return r
}

func sealStatusServer(initialized string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"initialized":` + initialized + `}`))
	}))
}

// A replica with a lost volume must not found a second cluster under its ID.
func TestGuardBootstrap(t *testing.T) {
	up := sealStatusServer("true")
	defer up.Close()
	fresh := sealStatusServer("false")
	defer fresh.Close()
	tok := filepath.Join(t.TempDir(), "vault-0")

	// An initialized peer and no token: refused, with the remedy in the error.
	r := guardOpts(t, "-raft-peers", up.URL, "-raft-join-token-file", tok)
	err := r.guardBootstrap(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "refusing to bootstrap") {
		t.Fatalf("err = %v, want refusal", err)
	}
	if r.retryAddrs() != nil {
		t.Fatal("refused node still has addresses to join")
	}

	// With a token it joins the existing cluster instead.
	if err := os.WriteFile(tok, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.guardBootstrap(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got := r.retryAddrs(); len(got) != 1 || got[0] != up.URL {
		t.Fatalf("retryAddrs = %v, want [%s]", got, up.URL)
	}

	// Uninitialized, unreachable and unset peers all leave bootstrap alone.
	for name, args := range map[string][]string{
		"uninitialized": {"-raft-peers", fresh.URL},
		"unreachable":   {"-raft-peers", "http://127.0.0.1:1"},
		"unset":         {},
	} {
		r := guardOpts(t, args...)
		if err := r.guardBootstrap(t.TempDir()); err != nil || r.retryAddrs() != nil {
			t.Fatalf("%s: err=%v addrs=%v", name, err, r.retryAddrs())
		}
	}

	// A node with Raft state never bootstraps, so the guard stays out.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "raft"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "raft", "raft.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r = guardOpts(t, "-raft-peers", up.URL)
	if err := r.guardBootstrap(dir); err != nil {
		t.Fatalf("node with state: %v", err)
	}
}

func TestSnapshotDigestIgnoresOrderAndCoordinationRecords(t *testing.T) {
	ctx := context.Background()
	write := func(entries ...*storage.Entry) string {
		m := storage.NewMemoryBackend()
		for _, e := range entries {
			_ = m.Put(ctx, e)
		}
		var buf bytes.Buffer
		if err := snapshot.Write(ctx, m, &buf); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	a := write(&storage.Entry{Key: "sys/a", Value: []byte("1")}, &storage.Entry{Key: "logical/b", Value: []byte("2")})
	b := write(&storage.Entry{Key: "logical/b", Value: []byte("2")}, &storage.Entry{Key: "sys/a", Value: []byte("1")},
		&storage.Entry{Key: "core/ha/raft-holder", Value: []byte("x")}, &storage.Entry{Key: "raft-internal/join-token/h", Value: []byte("y")})
	c := write(&storage.Entry{Key: "sys/a", Value: []byte("1")}, &storage.Entry{Key: "logical/b", Value: []byte("3")})

	na, sa, err := snapshotDigest(strings.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	nb, sb, _ := snapshotDigest(strings.NewReader(b))
	_, sc, _ := snapshotDigest(strings.NewReader(c))
	if na != 2 || nb != 2 || sa != sb {
		t.Fatalf("a=%d/%s b=%d/%s: coordination records must not count", na, sa, nb, sb)
	}
	if sa == sc {
		t.Fatal("a changed value did not change the digest")
	}
	if _, _, err := snapshotDigest(strings.NewReader("not a snapshot\n")); err == nil {
		t.Fatal("accepted a non-snapshot")
	}
}

func TestCompareSnapshots(t *testing.T) {
	ctx := context.Background()
	mk := func(kvs map[string]string) string {
		m := storage.NewMemoryBackend()
		for k, v := range kvs {
			_ = m.Put(ctx, &storage.Entry{Key: k, Value: []byte(v)})
		}
		var buf bytes.Buffer
		if err := snapshot.Write(ctx, m, &buf); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	export := mk(map[string]string{"a": "1", "b": "2", "c": "3"})
	migrated := mk(map[string]string{"a": "1", "b": "X", "d": "4", "core/ha/lock": "z"})
	missing, changed, added, err := compareSnapshots(strings.NewReader(export), strings.NewReader(migrated))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(missing, ",") != "c" || strings.Join(changed, ",") != "b" || strings.Join(added, ",") != "d" {
		t.Fatalf("missing=%v changed=%v added=%v", missing, changed, added)
	}
}
