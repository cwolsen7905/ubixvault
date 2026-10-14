package raft

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/cluster"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// lazyStore lets a Certs be built before the backend that stores its CA.
type lazyStore struct{ b atomic.Pointer[Backend] }

func (l *lazyStore) Get(ctx context.Context, k string) (*storage.Entry, error) {
	if b := l.b.Load(); b != nil {
		return b.Get(ctx, k)
	}
	return nil, errors.New("not open")
}

func (l *lazyStore) Put(ctx context.Context, e *storage.Entry) error {
	if b := l.b.Load(); b != nil {
		return b.Put(ctx, e)
	}
	return errors.New("not open")
}

type credFn struct{ c *cluster.Certs }

func (c credFn) RootCAs() *x509.CertPool         { return c.c.RootCAs() }
func (c credFn) Leaf() (*tls.Certificate, error) { return c.c.Leaf() }

// muxNode is a real node: Raft on the shared cluster listener, with Certs
// reading the CA from its own replicated store.
func muxNode(t *testing.T, id string, bootstrap bool) (*Backend, *cluster.Certs, *cluster.Mux) {
	t.Helper()
	store := &lazyStore{}
	certs := cluster.NewCerts(store)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := cluster.NewMux(ln, certs)
	t.Cleanup(func() { _ = mux.Close() })
	tr, err := NewMuxTransport(mux.Raft(), ln.Addr().String(), credFn{certs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, id, bootstrap, tr)
	b, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	store.b.Store(b)
	return b, certs, mux
}

// A fresh joiner that cannot read the barrier replicates over the bridge leaf,
// is promoted once it reports caught up, and then speaks with its own leaf.
func TestMuxClusterJoinWithBridge(t *testing.T) {
	ctx := ctxT(t)
	leader, lcerts, _ := muxNode(t, "n1", true)
	if err := leader.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lcerts.EnsureCA(ctx); err != nil {
		t.Fatal(err)
	}
	put(t, leader, "k", "v1")

	joiner, jcerts, _ := muxNode(t, "n2", false)
	// The joiner has no CA of its own yet (it replicates it), like a sealed
	// fresh node, so only the bridge works.
	tok, _, err := leader.MintJoinToken(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	br, err := leader.AcceptJoin(ctx, lcerts, tok, "n2", joinerAddr(t, joiner))
	if err != nil {
		t.Fatalf("AcceptJoin: %v", err)
	}
	if err := jcerts.SetBridge(br.CAPEM, br.CertPEM, br.KeyPEM); err != nil {
		t.Fatal(err)
	}
	eventually(t, "joiner to replicate", func() bool { return hasValue(joiner, "k", "v1") })

	// Without the bridge/CA a node is not a peer: a third node with no
	// credential never receives the data.
	stranger, _, _ := muxNode(t, "n3", false)
	if err := leader.AddNonvoter("n3", joinerAddr(t, stranger)); err != nil {
		t.Fatal(err)
	}
	put(t, leader, "k2", "v2")
	eventually(t, "joiner to get k2", func() bool { return hasValue(joiner, "k2", "v2") })
	if hasValue(stranger, "k2", "v2") || hasValue(stranger, "k", "v1") {
		t.Fatal("a node without cluster credentials replicated data")
	}
}

func joinerAddr(t *testing.T, b *Backend) string {
	t.Helper()
	return b.cfg.Transport.Addr()
}
