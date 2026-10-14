package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

type sealedStore struct{}

func (sealedStore) Get(context.Context, string) (*storage.Entry, error) {
	return nil, errors.New("sealed")
}
func (sealedStore) Put(context.Context, *storage.Entry) error { return errors.New("sealed") }

func startMux(t *testing.T, server *Certs) (*Mux, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMux(ln, server)
	t.Cleanup(func() { _ = m.Close() })
	return m, ln.Addr().String()
}

func dial(t *testing.T, addr string, cfg *tls.Config) (net.Conn, error) {
	t.Helper()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: cfg}
	return d.DialContext(context.Background(), "tcp", addr)
}

func TestMuxDispatchesByALPN(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryBackend()
	server, client := NewCerts(mem), NewCerts(mem)
	if err := server.EnsureCA(ctx); err != nil {
		t.Fatal(err)
	}
	m, addr := startMux(t, server)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "forwarded")
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(m.HTTP()) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Forwarding client (no ALPN) reaches HTTP.
	cfg, err := client.clientTLS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	resp, err := hc.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("forward GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "forwarded" {
		t.Fatalf("body = %q", body)
	}

	// Raft ALPN reaches the raft listener.
	rcfg := cfg.Clone()
	rcfg.NextProtos = []string{RaftALPN}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := m.Raft().Accept()
		if err == nil {
			accepted <- c
		}
	}()
	c, err := dial(t, addr, rcfg)
	if err != nil {
		t.Fatalf("raft dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("raft connection not delivered to the raft listener")
	}

	// No client certificate is refused (the failure surfaces on first use in TLS 1.3).
	nc := cfg.Clone()
	nc.Certificates = nil
	if c, err := dial(t, addr, nc); err == nil {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection without a client certificate was served")
		}
		_ = c.Close()
	}
}

func TestSealedReplicaUsesBridgeLeaf(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryBackend()
	active := NewCerts(mem)
	if err := active.EnsureCA(ctx); err != nil {
		t.Fatal(err)
	}
	joiner := NewCerts(sealedStore{})
	if joiner.RootCAs() != nil {
		t.Fatal("sealed joiner has a CA before the bridge is installed")
	}
	ca, cert, key, notAfter, err := active.IssueBridge(ctx)
	if err != nil || time.Until(notAfter) < 23*time.Hour {
		t.Fatalf("IssueBridge: %v %v", notAfter, err)
	}
	if err := joiner.SetBridge(ca, cert, key); err != nil {
		t.Fatal(err)
	}
	if joiner.RootCAs() == nil {
		t.Fatal("no CA after SetBridge")
	}
	// A bridge for a different CA is rejected.
	other := NewCerts(storage.NewMemoryBackend())
	_ = other.EnsureCA(ctx)
	oca, _, _, _, _ := other.IssueBridge(ctx)
	if err := joiner.SetBridge(oca, cert, key); err == nil {
		t.Fatal("bridge leaf accepted under a foreign CA")
	}

	// The sealed joiner can serve the mux and be dialed by the active replica.
	_, addr := startMux(t, joiner)
	cfg, err := active.clientTLS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.NextProtos = []string{RaftALPN}
	c, err := dial(t, addr, cfg)
	if err != nil {
		t.Fatalf("dial sealed joiner: %v", err)
	}
	_ = c.Close()

	// A sealed replica without a bridge refuses everyone.
	_, addr2 := startMux(t, NewCerts(sealedStore{}))
	if c, err := dial(t, addr2, cfg); err == nil {
		_ = c.Close()
		t.Fatal("sealed replica without a bridge completed a handshake")
	}
}

func TestExpiredBridgeIsNotUsed(t *testing.T) {
	ctx := context.Background()
	active := NewCerts(storage.NewMemoryBackend())
	_ = active.EnsureCA(ctx)
	ca, cert, key, _, _ := active.IssueBridge(ctx)
	j := NewCerts(sealedStore{})
	now := time.Now()
	j.now = func() time.Time { return now }
	if err := j.SetBridge(ca, cert, key); err != nil {
		t.Fatal(err)
	}
	j.now = func() time.Time { return now.Add(25 * time.Hour) }
	if j.RootCAs() != nil {
		t.Fatal("expired bridge still used")
	}
}

// toggleStore is a barrier that can be sealed and unsealed under a test.
type toggleStore struct {
	Storage
	sealed bool
}

func (s *toggleStore) Get(ctx context.Context, k string) (*storage.Entry, error) {
	if s.sealed {
		return nil, errors.New("sealed")
	}
	return s.Storage.Get(ctx, k)
}

func newBridge(t *testing.T) (ca, cert, key []byte, store storage.Backend) {
	t.Helper()
	store = storage.NewMemoryBackend()
	active := NewCerts(store)
	if err := active.EnsureCA(context.Background()); err != nil {
		t.Fatal(err)
	}
	ca, cert, key, _, err := active.IssueBridge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ca, cert, key, store
}

func TestBridgeSurvivesRestartUntilUnsealed(t *testing.T) {
	ca, cert, key, mem := newBridge(t)
	path := filepath.Join(t.TempDir(), "bridge.json")

	// First run: sealed joiner installs the bridge, which is persisted 0600.
	store := &toggleStore{Storage: mem, sealed: true}
	j := NewCerts(store)
	if err := j.PersistBridge(path); err != nil {
		t.Fatal(err)
	}
	if err := j.SetBridge(ca, cert, key); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("bridge file: %v mode=%v", err, st)
	}

	// Restart before the first unseal: a new process finds it.
	j2 := NewCerts(store)
	if err := j2.PersistBridge(path); err != nil {
		t.Fatal(err)
	}
	if j2.RootCAs() == nil {
		t.Fatal("restarted joiner lost its bridge credential")
	}

	// Once the barrier is readable the credential is dropped from disk.
	store.sealed = false
	if j2.RootCAs() == nil {
		t.Fatal("unsealed replica has no identity")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bridge file still present after unseal: %v", err)
	}
}

func TestExpiredPersistedBridgeIsDiscarded(t *testing.T) {
	ca, cert, key, _ := newBridge(t)
	path := filepath.Join(t.TempDir(), "bridge.json")
	if err := writeBridgeFile(path, ca, cert, key); err != nil {
		t.Fatal(err)
	}
	j := NewCerts(sealedStore{})
	j.now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	if err := j.PersistBridge(path); err != nil {
		t.Fatal(err)
	}
	if j.RootCAs() != nil {
		t.Fatal("expired persisted bridge was used")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired bridge file kept: %v", err)
	}
}

func TestCorruptPersistedBridgeIsDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := NewCerts(sealedStore{})
	if err := j.PersistBridge(path); err != nil {
		t.Fatalf("PersistBridge on a corrupt file = %v, want it ignored", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt bridge file kept")
	}
}

// A sealed joiner holding only a bridge leaf can make a request of its own to
// the active replica's cluster listener (the applied-index report), and the
// handler sees it as a direct peer rather than a forwarded client.
func TestSealedJoinerHTTPClientReachesActive(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryBackend()
	active := NewCerts(mem)
	if err := active.EnsureCA(ctx); err != nil {
		t.Fatal(err)
	}
	m, addr := startMux(t, active)
	var direct atomic.Bool
	srv := &http.Server{
		Handler: ServerHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			direct.Store(DirectPeer(r))
			w.WriteHeader(http.StatusNoContent)
		}), func() bool { return true }),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = srv.Serve(m.HTTP()) }()
	t.Cleanup(func() { _ = srv.Close() })

	ca, cert, key, _, err := active.IssueBridge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	joiner := NewCerts(sealedStore{})
	if err := joiner.SetBridge(ca, cert, key); err != nil {
		t.Fatal(err)
	}
	resp, err := joiner.HTTPClient().Post("https://"+addr+"/x", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("joiner request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || !direct.Load() {
		t.Fatalf("status %d, direct=%v", resp.StatusCode, direct.Load())
	}

	// Without a bridge there is no identity to dial with.
	if r, err := NewCerts(sealedStore{}).HTTPClient().Post("https://"+addr+"/x", "application/json", nil); err == nil {
		_ = r.Body.Close()
		t.Fatal("a sealed replica with no bridge reached the cluster listener")
	}
}
