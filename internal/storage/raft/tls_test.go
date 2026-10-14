package raft

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/cwolsen7905/ubixvault/internal/storage"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

var serial atomic.Int64

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) leaf(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "node"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (ca *testCA) creds(t *testing.T) Credentials {
	return StaticCredentials{CA: ca.pool, Cert: ca.leaf(t, time.Now().Add(time.Hour))}
}

func newTLSTransport(t *testing.T, c Credentials) *Transport {
	t.Helper()
	tr, err := NewTLSTransport("127.0.0.1:0", "", c, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// tlsCluster starts n nodes over mTLS TCP: n1 bootstraps, the rest are voters.
func tlsCluster(t *testing.T, n int) (*testCA, []*Backend, []*Transport) {
	t.Helper()
	ca := newTestCA(t)
	var bs []*Backend
	var trs []*Transport
	for i := 1; i <= n; i++ {
		tr := newTLSTransport(t, ca.creds(t))
		b, err := Open(testConfig(t, fmt.Sprintf("n%d", i), i == 1, tr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = b.Close() })
		bs, trs = append(bs, b), append(trs, tr)
	}
	if err := bs[0].WaitForLeader(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < n; i++ {
		if err := bs[0].AddVoter(fmt.Sprintf("n%d", i+1), trs[i].Addr()); err != nil {
			t.Fatal(err)
		}
	}
	return ca, bs, trs
}

func TestTLSClusterReplicates(t *testing.T) {
	_, bs, _ := tlsCluster(t, 3)
	ctx := ctxT(t)
	if err := bs[0].Put(ctx, &storage.Entry{Key: "a/b", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	for i, b := range bs {
		eventually(t, fmt.Sprintf("n%d replicated", i+1), func() bool {
			e, err := b.Get(ctx, "a/b")
			return err == nil && e != nil && string(e.Value) == "v"
		})
	}
}

// handshake dials addr with cfg and reports whether the server kept the
// connection (TLS 1.3 surfaces a server-side rejection on first read).
func handshake(t *testing.T, addr string, cfg *tls.Config) error {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil // server holds the connection open: accepted
	}
	return err
}

func TestTLSRejectsUnauthorizedPeers(t *testing.T) {
	ca := newTestCA(t)
	srv := newTLSTransport(t, ca.creds(t))
	addr := srv.Addr()
	other := newTestCA(t)

	base := func(cert *tls.Certificate, protos []string) *tls.Config {
		c := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: protos}
		if cert != nil {
			c.Certificates = []tls.Certificate{*cert}
		}
		return c
	}
	good := ca.leaf(t, time.Now().Add(time.Hour))
	if err := handshake(t, addr, base(&good, []string{ALPNProtocol})); err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}
	wrong := other.leaf(t, time.Now().Add(time.Hour))
	expired := ca.leaf(t, time.Now().Add(-time.Minute))
	for name, cfg := range map[string]*tls.Config{
		"no cert":    base(nil, []string{ALPNProtocol}),
		"wrong CA":   base(&wrong, []string{ALPNProtocol}),
		"expired":    base(&expired, []string{ALPNProtocol}),
		"wrong ALPN": base(&good, []string{"h2"}),
		"no ALPN":    base(&good, nil),
	} {
		if err := handshake(t, addr, cfg); err == nil {
			t.Errorf("%s: peer accepted, want rejection", name)
		}
	}

	// A server that does not chain to our CA is refused by the dialer too.
	rogue := newTLSTransport(t, other.creds(t))
	cl := &tlsStream{creds: ca.creds(t)}
	if conn, err := cl.Dial(hraft.ServerAddress(rogue.Addr()), 3*time.Second); err == nil {
		_ = conn.Close()
		t.Error("dialed a server outside the cluster CA")
	}
}

func TestJoinTokenLifecycle(t *testing.T) {
	c := newCluster(t, 1, nil)
	b := c.waitLeader()
	ctx := ctxT(t)

	tok, exp, err := b.MintJoinToken(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 14*time.Minute || d > DefaultJoinTokenTTL {
		t.Errorf("default TTL off: %v", d)
	}
	if err := b.RedeemJoinToken(ctx, tok); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if err := b.RedeemJoinToken(ctx, tok); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("reuse: %v, want ErrTokenUsed", err)
	}
	if err := b.RedeemJoinToken(ctx, tokenScheme+"AAAA"); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("garbage: %v", err)
	}
	other, _, _ := b.MintJoinToken(ctx, time.Minute)
	tampered := other[:len(other)-1] + "A"
	if tampered == other {
		tampered = other[:len(other)-1] + "B"
	}
	if err := b.RedeemJoinToken(ctx, tampered); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("tampered: %v", err)
	}

	short, _, _ := b.MintJoinToken(ctx, 30*time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if err := b.RedeemJoinToken(ctx, short); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired: %v", err)
	}
	// The token store is not reachable through the public key space.
	if err := b.Put(ctx, &storage.Entry{Key: tokenPrefix + "x", Value: []byte("y")}); err == nil {
		t.Error("Put into token prefix accepted")
	}
	// A burn does not fail the state machine.
	if err := b.Put(ctx, &storage.Entry{Key: "ok", Value: []byte("1")}); err != nil {
		t.Errorf("backend unhealthy after token errors: %v", err)
	}
}

func TestJoinTokenConcurrentRedeemSingleWinner(t *testing.T) {
	c := newCluster(t, 1, nil)
	b := c.waitLeader()
	ctx := ctxT(t)
	tok, _, _ := b.MintJoinToken(ctx, time.Minute)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.RedeemJoinToken(context.Background(), tok) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d redemptions succeeded, want 1", wins.Load())
	}
}

func TestJoinOverTLSAddsNonvoter(t *testing.T) {
	ca, bs, _ := tlsCluster(t, 1)
	ctx := ctxT(t)
	tr := newTLSTransport(t, ca.creds(t))
	nb, err := Open(testConfig(t, "j1", false, tr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nb.Close() })

	tok, _, _ := bs[0].MintJoinToken(ctx, time.Minute)
	if err := bs[0].JoinNode(ctx, tok, "j1", tr.Addr()); err != nil {
		t.Fatal(err)
	}
	if err := bs[0].JoinNode(ctx, tok, "j2", "127.0.0.1:1"); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("reused token joined a node: %v", err)
	}
	_ = bs[0].Put(ctx, &storage.Entry{Key: "k", Value: []byte("v")})
	eventually(t, "joiner replicated", func() bool {
		e, err := nb.Get(ctx, "k")
		return err == nil && e != nil
	})
	cfg, _ := bs[0].Configuration()
	for _, s := range cfg {
		if s.ID == "j1" && s.Voter {
			t.Error("joiner is a voter before promotion")
		}
	}
}
