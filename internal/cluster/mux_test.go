package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
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
