package raft

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/cluster"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// lazyCerts lets a transport be built before the node's cluster.Certs exists.
type lazyCerts struct{ c atomic.Pointer[cluster.Certs] }

func (l *lazyCerts) RootCAs() *x509.CertPool {
	if c := l.c.Load(); c != nil {
		return c.RootCAs()
	}
	return nil
}

func (l *lazyCerts) Leaf() (*tls.Certificate, error) {
	if c := l.c.Load(); c != nil {
		return c.Leaf()
	}
	return nil, errors.New("no identity yet")
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

type rotNode struct {
	dir, id, addr string
	b             *Backend
	certs         *cluster.Certs
}

func (n *rotNode) open(t *testing.T, bootstrap bool) {
	t.Helper()
	lc := &lazyCerts{}
	tr, err := NewTLSTransport(n.addr, "", lc, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, n.id, bootstrap, tr)
	cfg.DataDir = n.dir
	n.b, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.certs = cluster.NewCerts(n.b)
	lc.c.Store(n.certs)
}

// TestCARotationThenRestartReconverges is the basis of the runbook: after
// Rotate on the leader, restarting the nodes reloads the new CA from their
// replicated state and the cluster serves writes again, without a re-seat.
func TestCARotationThenRestartReconverges(t *testing.T) {
	ctx := ctxT(t)
	nodes := []*rotNode{
		{dir: t.TempDir(), id: "n1", addr: freeAddr(t)},
		{dir: t.TempDir(), id: "n2", addr: freeAddr(t)},
		{dir: t.TempDir(), id: "n3", addr: freeAddr(t)},
	}
	n1 := nodes[0]
	n1.open(t, true)
	t.Cleanup(func() {
		for _, n := range nodes {
			if n.b != nil {
				_ = n.b.Close()
			}
		}
	})
	if err := n1.b.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n1.certs.EnsureCA(ctx); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes[1:] {
		n.open(t, false)
		ca, cert, key, _, err := n1.certs.IssueBridge(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.certs.SetBridge(ca, cert, key); err != nil {
			t.Fatal(err)
		}
		if err := n1.b.AddVoter(n.id, n.addr); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range nodes {
		eventually(t, n.id+" has the CA", func() bool {
			e, err := n.b.Get(ctx, "sys/ha/cluster-ca")
			return err == nil && e != nil
		})
	}
	old, _ := n1.b.Get(ctx, "sys/ha/cluster-ca")

	if err := n1.certs.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	for _, n := range nodes[1:] {
		eventually(t, n.id+" has the new CA", func() bool {
			e, err := n.b.Get(ctx, "sys/ha/cluster-ca")
			return err == nil && e != nil && string(e.Value) != string(old.Value)
		})
	}

	// Restart everyone: leaves are memory-only, so each node loads the new CA.
	for _, n := range nodes {
		if err := n.b.Close(); err != nil {
			t.Fatal(err)
		}
		n.open(t, false)
	}
	var leader *rotNode
	eventually(t, "a leader after restart", func() bool {
		for _, n := range nodes {
			if n.b.IsLeader() {
				leader = n
				return true
			}
		}
		return false
	})
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := leader.b.Put(wctx, &storage.Entry{Key: "after/rotation", Value: []byte("1")}); err != nil {
		t.Fatalf("write after rotation: %v", err)
	}
	for _, n := range nodes {
		eventually(t, n.id+" replicated", func() bool {
			e, err := n.b.Get(ctx, "after/rotation")
			return err == nil && e != nil
		})
	}
}
