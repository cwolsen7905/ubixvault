package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"
)

// RaftALPN is the application protocol that selects Raft on the cluster
// listener; every other (or no) protocol is the request-forwarding HTTP
// protocol. It must equal raft.ALPNProtocol.
const RaftALPN = "ubixvault-raft/1"

// Credentials is a replica's cluster identity, as [Certs] provides.
type Credentials interface {
	RootCAs() *x509.CertPool
	Leaf() (*tls.Certificate, error)
}

// Mux serves both cluster protocols on one listener (docs/design/raft-storage.md
// "TLS between peers"): it terminates mutual TLS 1.3 against the cluster CA and
// hands each connection to the Raft or HTTP side by negotiated ALPN. The
// credentials are consulted per handshake, so nothing is served while sealed.
type Mux struct {
	ln    net.Listener
	creds Credentials
	raft  *chanListener
	http  *chanListener
	once  sync.Once
}

// NewMux starts dispatching connections accepted from ln.
func NewMux(ln net.Listener, creds Credentials) *Mux {
	m := &Mux{ln: ln, creds: creds, raft: newChanListener(ln.Addr()), http: newChanListener(ln.Addr())}
	go m.acceptLoop()
	return m
}

// Raft yields authenticated connections that negotiated [RaftALPN].
func (m *Mux) Raft() net.Listener { return m.raft }

// HTTP yields authenticated connections for the forwarding protocol.
func (m *Mux) HTTP() net.Listener { return m.http }

// Close stops the listener and both sides.
func (m *Mux) Close() error {
	var err error
	m.once.Do(func() {
		err = m.ln.Close()
		_ = m.raft.Close()
		_ = m.http.Close()
	})
	return err
}

func (m *Mux) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{RaftALPN, "http/1.1"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool := m.creds.RootCAs()
			if pool == nil {
				return nil, errors.New("cluster: no cluster CA available")
			}
			leaf, err := m.creds.Leaf()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{RaftALPN, "http/1.1"},
				Certificates: []tls.Certificate{*leaf},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    pool,
			}, nil
		},
	}
}

func (m *Mux) acceptLoop() {
	cfg := m.tlsConfig()
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // transient (e.g. fd exhaustion)
			continue
		}
		go m.dispatch(tls.Server(conn, cfg))
	}
}

func (m *Mux) dispatch(c *tls.Conn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	dst := m.http
	if c.ConnectionState().NegotiatedProtocol == RaftALPN {
		dst = m.raft
	}
	if !dst.push(c) {
		_ = c.Close()
	}
}

// chanListener is a net.Listener fed by the mux.
type chanListener struct {
	addr   net.Addr
	ch     chan net.Conn
	done   chan struct{}
	closed sync.Once
}

func newChanListener(a net.Addr) *chanListener {
	return &chanListener{addr: a, ch: make(chan net.Conn, 16), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	case <-time.After(5 * time.Second): // the consumer is not draining; shed load
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
