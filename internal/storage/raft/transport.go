package raft

import (
	"fmt"
	"io"
	"net"
	"time"

	hraft "github.com/hashicorp/raft"
)

// Transport carries Raft RPCs between peers. It wraps the consensus library's
// transport so callers need not import it.
type Transport struct {
	t    hraft.Transport
	addr hraft.ServerAddress
	// inmem is non-nil for in-memory transports, which must be wired to peers.
	inmem *hraft.InmemTransport
}

// Addr is the address peers use to reach this transport.
func (t *Transport) Addr() string { return string(t.addr) }

// NewInmemTransport returns an in-process transport for tests. Peers must be
// introduced to each other with [Transport.Connect].
func NewInmemTransport(addr string) *Transport {
	a, it := hraft.NewInmemTransport(hraft.ServerAddress(addr))
	return &Transport{t: it, addr: a, inmem: it}
}

// Connect makes peer reachable from t (in-memory transports only). Connect both
// directions for a pair that must talk. Disconnect a peer with [Transport.Disconnect]
// to simulate a partition.
func (t *Transport) Connect(peer *Transport) {
	if t.inmem != nil && peer.inmem != nil {
		t.inmem.Connect(peer.addr, peer.inmem)
	}
}

// Disconnect severs the path from t to the peer address (in-memory only).
func (t *Transport) Disconnect(peerAddr string) {
	if t.inmem != nil {
		t.inmem.Disconnect(hraft.ServerAddress(peerAddr))
	}
}

// NewTCPTransport listens on bind and advertises advertise (the bound address if
// empty, which must then not be unspecified).
//
// The stream is plaintext TCP and suitable for loopback tests only. Peer
// authentication over the cluster CA, multiplexed onto the cluster listener, is
// a later slice (docs/design/raft-storage.md "TLS between peers").
func NewTCPTransport(bind, advertise string, logOut io.Writer) (*Transport, error) {
	var adv net.Addr // nil: advertise the address actually bound
	if advertise != "" {
		a, err := net.ResolveTCPAddr("tcp", advertise)
		if err != nil {
			return nil, fmt.Errorf("raft: resolve advertise address: %w", err)
		}
		adv = a
	}
	nt, err := hraft.NewTCPTransportWithLogger(bind, adv, 3, 10*time.Second, newLogger("transport", logOut))
	if err != nil {
		return nil, fmt.Errorf("raft: tcp transport: %w", err)
	}
	return &Transport{t: nt, addr: nt.LocalAddr()}, nil
}
