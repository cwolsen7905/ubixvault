package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/api"
	"github.com/cwolsen7905/ubixvault/internal/cluster"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

// raftOpts are the -raft-* server flags (docs/design/raft-storage.md).
type raftOpts struct {
	nodeID    *string
	advertise *string
	bootstrap *bool
}

func raftFlags(fs *flag.FlagSet) *raftOpts {
	return &raftOpts{
		nodeID: fs.String("raft-node-id", os.Getenv("UBIXVAULT_RAFT_NODE_ID"),
			"stable node ID in the Raft cluster (default: hostname; or $UBIXVAULT_RAFT_NODE_ID)"),
		advertise: fs.String("raft-advertise-addr", os.Getenv("UBIXVAULT_RAFT_ADVERTISE_ADDR"),
			"host:port other nodes reach this one's cluster listener on (default: host of -ha-cluster-addr)"),
		bootstrap: fs.Bool("raft-bootstrap", !envFalse("UBIXVAULT_RAFT_BOOTSTRAP"),
			"start an empty data directory as a single-voter cluster; set false on nodes that will join an existing one"),
	}
}

func envFalse(name string) bool {
	switch os.Getenv(name) {
	case "0", "false", "FALSE", "no":
		return true
	}
	return false
}

// deriveClusterAddrs fills in the cluster listener's bind and URL defaults
// from -listen and $POD_IP, as HA always has.
func deriveClusterAddrs(listen string, clusterListen, clusterAddr *string) error {
	if *clusterListen == "" {
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return fmt.Errorf("derive -ha-cluster-listen from -listen %q: %w", listen, err)
		}
		*clusterListen = net.JoinHostPort(host, "8201")
	}
	if *clusterAddr == "" {
		// The cluster listener is always TLS, whatever the API does.
		a, err := defaultAdvertise(*clusterListen, true)
		if err != nil {
			return err
		}
		*clusterAddr = a
	}
	return nil
}

// lazyCreds is the Raft transport's credentials before the barrier exists:
// the transport must be built to open storage, and the barrier is built on
// storage. Until set, every handshake is refused, which is also the "a sealed
// replica does not vote" rule.
type lazyCreds struct{ c atomic.Pointer[cluster.Certs] }

func (l *lazyCreds) set(c *cluster.Certs) { l.c.Store(c) }

func (l *lazyCreds) RootCAs() *x509.CertPool {
	if c := l.c.Load(); c != nil {
		return c.RootCAs()
	}
	return nil
}

func (l *lazyCreds) Leaf() (*tls.Certificate, error) {
	if c := l.c.Load(); c != nil {
		return c.Leaf()
	}
	return nil, errors.New("cluster identity not available yet")
}

func (r *raftOpts) resolve(clusterAddr string) (nodeID, advertise string, err error) {
	nodeID = *r.nodeID
	if nodeID == "" {
		if nodeID, err = os.Hostname(); err != nil {
			return "", "", fmt.Errorf("-raft-node-id is required (hostname: %w)", err)
		}
	}
	advertise = *r.advertise
	if advertise == "" {
		u, err := url.Parse(clusterAddr)
		if err != nil || u.Host == "" {
			return "", "", fmt.Errorf("set -raft-advertise-addr (cannot derive it from %q)", clusterAddr)
		}
		advertise = u.Host
	}
	return nodeID, advertise, nil
}

// openRaft starts this node: the cluster listener (shared with request
// forwarding by ALPN) and the Raft backend on it.
func openRaft(r *raftOpts, dataDir, clusterListen, clusterAddr string, creds cluster.Credentials) (*cluster.Mux, *raftstore.Backend, error) {
	if dataDir == "" {
		return nil, nil, errors.New("-storage raft requires -data <dir>")
	}
	nodeID, advertise, err := r.resolve(clusterAddr)
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", clusterListen)
	if err != nil {
		return nil, nil, fmt.Errorf("-storage raft: cluster listener: %w", err)
	}
	mux := cluster.NewMux(ln, creds)
	tr, err := raftstore.NewMuxTransport(mux.Raft(), advertise, creds, os.Stderr)
	if err != nil {
		_ = mux.Close()
		return nil, nil, err
	}
	b, err := raftstore.Open(raftstore.Config{
		NodeID: nodeID, DataDir: dataDir, Transport: tr,
		Bootstrap: *r.bootstrap, LogOutput: os.Stderr,
	})
	if err != nil {
		_ = mux.Close()
		return nil, nil, err
	}
	return mux, b, nil
}

// raftGauges exposes the node's consensus counters on /v1/sys/metrics.
func raftGauges(b *raftstore.Backend) []api.Option {
	g := func(name, help string, f func(raftstore.Stats) float64) api.Option {
		return api.WithGauge(name, help, func() float64 { return f(b.Stats()) })
	}
	flag := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	return []api.Option{
		g("ubixvault_raft_term", "Current Raft term.", func(s raftstore.Stats) float64 { return float64(s.Term) }),
		g("ubixvault_raft_last_index", "Last Raft log index on this node.", func(s raftstore.Stats) float64 { return float64(s.LastIndex) }),
		g("ubixvault_raft_applied_index", "Last Raft log index applied to this node's state machine.", func(s raftstore.Stats) float64 { return float64(s.AppliedIndex) }),
		g("ubixvault_raft_is_leader", "1 if this node is the Raft leader.", func(s raftstore.Stats) float64 { return flag(s.Leader) }),
		g("ubixvault_raft_voters", "Voting members in the Raft configuration.", func(s raftstore.Stats) float64 { return float64(s.Voters) }),
		g("ubixvault_raft_nonvoters", "Non-voting members in the Raft configuration.", func(s raftstore.Stats) float64 { return float64(s.Nonvoters) }),
		g("ubixvault_raft_failed", "1 if this node's state machine failed and it refuses writes.", func(s raftstore.Stats) float64 { return flag(s.Failed) }),
	}
}

// restoreIntoRaft restores a snapshot offline into a Raft data directory that
// no server is using: it brings up a one-voter cluster in memory under the
// node's real ID and advertise address (they are persisted in the
// configuration), restores, and stops. Start the server on the directory
// afterwards; other nodes join it.
func restoreIntoRaft(r *raftOpts, dataDir string, snap io.Reader) error {
	if dataDir == "" {
		return errors.New("-storage raft requires -data <dir>")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "raft", "raft.db")); err == nil {
		return fmt.Errorf("%s already holds Raft state; restore into an empty directory, or restore through the running cluster", dataDir)
	}
	nodeID, advertise, err := r.resolve("")
	if err != nil && *r.advertise == "" {
		return errors.New("restore into raft needs -raft-advertise-addr (it is persisted in the cluster configuration)")
	} else if err != nil {
		return err
	}
	tr := raftstore.NewInmemTransport(advertise)
	b, err := raftstore.Open(raftstore.Config{NodeID: nodeID, DataDir: dataDir, Transport: tr, Bootstrap: true})
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := b.WaitForLeader(ctx); err != nil {
		return fmt.Errorf("raft: no leader: %w", err)
	}
	// The bootstrap configuration entry must be applied before a restore is
	// accepted; a barrier waits for it.
	for !b.IsLeader() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("raft: not elected: %w", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := b.Barrier(); err != nil {
		return fmt.Errorf("raft: barrier: %w", err)
	}
	return b.RestoreSnapshot(ctx, snap)
}
