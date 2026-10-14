package raft

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	hraft "github.com/hashicorp/raft"
)

// ALPNProtocol is the application protocol a peer must negotiate on the
// cluster listener to speak Raft (docs/design/raft-storage.md "TLS between
// peers"). The listener's other protocols are dispatched on other values.
const ALPNProtocol = "ubixvault-raft/1"

// Credentials is a node's cluster-CA identity. The raft package does not know
// where the CA lives (the barrier, `sys/ha/cluster-ca`); the caller supplies
// it. Both methods are consulted on every handshake, so a rotated leaf or CA
// takes effect on the next connection without restarting the transport.
type Credentials interface {
	// RootCAs is the pool a peer's leaf must chain to.
	RootCAs() *x509.CertPool
	// Leaf is this node's current certificate, used as both server and client
	// identity.
	Leaf() (*tls.Certificate, error)
}

// StaticCredentials is a fixed [Credentials], for tests and single-shot use.
type StaticCredentials struct {
	CA   *x509.CertPool
	Cert tls.Certificate
}

// RootCAs implements [Credentials].
func (s StaticCredentials) RootCAs() *x509.CertPool { return s.CA }

// Leaf implements [Credentials].
func (s StaticCredentials) Leaf() (*tls.Certificate, error) { return &s.Cert, nil }

// tlsStream is a [hraft.StreamLayer] doing mutual TLS 1.3 on the cluster CA.
type tlsStream struct {
	ln    net.Listener
	adv   net.Addr
	creds Credentials
}

func (s *tlsStream) Accept() (net.Conn, error) { return s.ln.Accept() }
func (s *tlsStream) Close() error              { return s.ln.Close() }
func (s *tlsStream) Addr() net.Addr {
	if s.adv != nil {
		return s.adv
	}
	return s.ln.Addr()
}

func (s *tlsStream) Dial(addr hraft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: s.clientConfig()}
	return d.DialContext(ctx, "tcp", string(addr))
}

// verifyPeer authenticates a peer purely by chain to the cluster CA: leaves
// carry no stable DNS name (the design issues them in memory per node), so
// hostname verification is replaced by CA membership, expiry and ALPN.
func verifyPeer(creds Credentials) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol != ALPNProtocol {
			return fmt.Errorf("raft: peer negotiated %q, want %q", cs.NegotiatedProtocol, ALPNProtocol)
		}
		if len(cs.PeerCertificates) == 0 {
			return errors.New("raft: peer presented no certificate")
		}
		roots := creds.RootCAs()
		if roots == nil {
			return errors.New("raft: no cluster CA available")
		}
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		return err
	}
}

func (s *tlsStream) base() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPNProtocol},
		InsecureSkipVerify: true, //nolint:gosec // chain, expiry and ALPN are enforced in VerifyConnection (verifyPeer)
		VerifyConnection:   verifyPeer(s.creds),
	}
}

func (s *tlsStream) clientConfig() *tls.Config {
	c := s.base()
	c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return s.creds.Leaf()
	}
	return c
}

func (s *tlsStream) serverConfig() *tls.Config {
	c := s.base()
	c.ClientAuth = tls.RequireAnyClientCert // chain checked in VerifyConnection
	c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return s.creds.Leaf()
	}
	return c
}

// NewTLSTransport listens on bind with mutual TLS and advertises advertise
// (the bound address if empty). Peers without a leaf chaining to creds'
// cluster CA, or that do not negotiate [ALPNProtocol], are refused during the
// handshake. This replaces [NewTCPTransport] for anything but loopback tests.
func NewTLSTransport(bind, advertise string, creds Credentials, logOut io.Writer) (*Transport, error) {
	if creds == nil {
		return nil, errors.New("raft: tls transport requires credentials")
	}
	var adv net.Addr
	if advertise != "" {
		a, err := net.ResolveTCPAddr("tcp", advertise)
		if err != nil {
			return nil, fmt.Errorf("raft: resolve advertise address: %w", err)
		}
		adv = a
	}
	s := &tlsStream{adv: adv, creds: creds}
	ln, err := tls.Listen("tcp", bind, s.serverConfig())
	if err != nil {
		return nil, fmt.Errorf("raft: tls listen: %w", err)
	}
	s.ln = ln
	if s.adv == nil {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.IP.IsUnspecified() {
			_ = ln.Close()
			return nil, errors.New("raft: advertise address required when binding an unspecified address")
		}
	}
	nt := hraft.NewNetworkTransportWithConfig(&hraft.NetworkTransportConfig{
		Stream:  s,
		MaxPool: 3,
		Timeout: 10 * time.Second,
		Logger:  newLogger("transport", logOut),
	})
	return &Transport{t: nt, addr: nt.LocalAddr()}, nil
}

// NewMuxTransport is [NewTLSTransport] for a listener that is shared with other
// protocols: ln yields connections whose TLS handshake is already done and
// whose peer has already been authenticated against the cluster CA and ALPN
// (the cluster listener's mux does both before dispatching on
// [ALPNProtocol]). Outbound connections are dialed with creds exactly as in
// [NewTLSTransport]. advertise is required: the shared listener's own address
// is not necessarily one peers can reach.
func NewMuxTransport(ln net.Listener, advertise string, creds Credentials, logOut io.Writer) (*Transport, error) {
	if creds == nil || ln == nil {
		return nil, errors.New("raft: mux transport requires a listener and credentials")
	}
	if advertise == "" {
		return nil, errors.New("raft: mux transport requires an advertise address")
	}
	adv, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		return nil, fmt.Errorf("raft: resolve advertise address: %w", err)
	}
	s := &tlsStream{ln: ln, adv: adv, creds: creds}
	nt := hraft.NewNetworkTransportWithConfig(&hraft.NetworkTransportConfig{
		Stream:  s,
		MaxPool: 3,
		Timeout: 10 * time.Second,
		Logger:  newLogger("transport", logOut),
	})
	return &Transport{t: nt, addr: nt.LocalAddr()}, nil
}
