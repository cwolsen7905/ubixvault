package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/api"
	"github.com/cwolsen7905/ubixvault/internal/cluster"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

// bridgeInstaller is what a join needs of the cluster identity: somewhere to
// put the credential the leader returns (cluster.Certs).
type bridgeInstaller interface {
	SetBridge(caPEM, certPEM, keyPEM []byte) error
}

// raftJoiner is the joining node's side of a join: it asks a leader to admit
// it and keeps the bridge credential it gets back. It serves both the operator
// call (`operator raft join`) and the declarative -raft-retry-join loop.
type raftJoiner struct {
	nodeID, advertise string
	certs             bridgeInstaller
	node              interface {
		Configuration() ([]raftstore.Server, error)
	}
	backoffMin, backoffMax time.Duration

	// ctx outlives a request: a retrying join keeps running under it.
	ctx context.Context
}

const (
	joinInitialBackoff = time.Second
	joinBackoffCap     = 30 * time.Second
	joinAttempt        = 15 * time.Second
)

// member reports whether this node is already in the Raft configuration, i.e.
// it joined earlier (the configuration is persisted).
func (j *raftJoiner) member() bool {
	servers, err := j.node.Configuration()
	if err != nil {
		return false
	}
	for _, s := range servers {
		if s.ID == j.nodeID {
			return true
		}
	}
	return false
}

// joinResponse mirrors the leader's join-accept reply.
type joinResponse struct {
	CACert string `json:"ca_cert"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
}

// once makes a single attempt against one leader API address. The token is
// never logged or included in an error.
func (j *raftJoiner) once(ctx context.Context, leaderAddr, caPEM, token string) error {
	hc := &http.Client{Timeout: joinAttempt}
	if caPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return errors.New("leader_ca_cert holds no PEM certificate")
		}
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	}
	body, err := json.Marshal(map[string]string{
		"join_token": token, "node_id": j.nodeID, "address": j.advertise,
	})
	if err != nil {
		return err
	}
	url := strings.TrimRight(leaderAddr, "/") + "/v1/sys/storage/raft/join-accept"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("leader address %q: %w", leaderAddr, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("contact %s: %w", leaderAddr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read join response from %s: %w", leaderAddr, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("%s answered %d: %s", leaderAddr, resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	var jr joinResponse
	if err := json.Unmarshal(data, &jr); err != nil {
		return fmt.Errorf("decode join response from %s: %w", leaderAddr, err)
	}
	return j.certs.SetBridge([]byte(jr.CACert), []byte(jr.Cert), []byte(jr.Key))
}

// Join implements api.RaftOptions.Join.
func (j *raftJoiner) Join(ctx context.Context, req api.RaftJoinRequest) (bool, error) {
	if j.member() {
		return true, nil
	}
	if req.Retry {
		go j.retry(j.ctx, []string{req.LeaderAPIAddr}, req.LeaderCACert, func() (string, error) { return req.JoinToken, nil })
		return false, nil
	}
	if err := j.once(ctx, req.LeaderAPIAddr, req.LeaderCACert, req.JoinToken); err != nil {
		return false, err
	}
	return true, nil
}

// retry joins through addrs with backoff until it succeeds, the node is a
// member, or ctx ends. token is re-read on every round so a rotated Secret is
// picked up; a token that was burned by a response that never arrived needs a
// new one and shows in the log as repeated refusals.
func (j *raftJoiner) retry(ctx context.Context, addrs []string, caPEM string, token func() (string, error)) {
	lo, hi := j.backoffMin, j.backoffMax
	if lo <= 0 {
		lo = joinInitialBackoff
	}
	if hi <= 0 {
		hi = joinBackoffCap
	}
	wait := lo
	for {
		if j.member() {
			return
		}
		tok, err := token()
		if err != nil {
			log.Printf("raft: retry-join: %v", err) //nolint:gosec // G706: error text names a file path or variable, never the token
		} else {
			for _, a := range addrs {
				if err = j.once(ctx, a, caPEM, tok); err == nil {
					log.Printf("raft: joined the cluster through %s as %q (non-voter until caught up)", a, j.nodeID) //nolint:gosec // G706: operator-configured address and node ID
					return
				}
				log.Printf("raft: retry-join: %v", err) //nolint:gosec // G706: error text carries only operator-configured addresses and server messages
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, hi)
	}
}

// tokenSource reads the join token from the file when set, else the
// environment. Never from a flag: arguments are visible in process listings.
func tokenSource(file string) func() (string, error) {
	return func() (string, error) {
		if file != "" {
			b, err := os.ReadFile(file) //nolint:gosec // G304: operator-provided path
			if err != nil {
				return "", fmt.Errorf("read -raft-join-token-file: %w", err)
			}
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, nil
			}
			return "", errors.New("-raft-join-token-file is empty")
		}
		if t := os.Getenv("UBIXVAULT_RAFT_JOIN_TOKEN"); t != "" {
			return t, nil
		}
		return "", errors.New("no join token: set -raft-join-token-file or $UBIXVAULT_RAFT_JOIN_TOKEN")
	}
}

// appliedReporter tells the leader how far this node's state machine has got,
// while it is a non-voter, so the leader can promote it. Reports go over the
// cluster listener under mutual TLS, so they work while this node is sealed.
type appliedReporter struct {
	nodeID string
	node   interface {
		Configuration() ([]raftstore.Server, error)
		Leader() (id, addr string)
		AppliedIndex() uint64
	}
	hc       *http.Client
	interval time.Duration
}

func newAppliedReporter(nodeID string, node *raftstore.Backend, certs *cluster.Certs) *appliedReporter {
	return &appliedReporter{nodeID: nodeID, node: node, hc: certs.HTTPClient(), interval: time.Second}
}

func (a *appliedReporter) run(ctx context.Context) {
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_ = a.reportOnce(ctx) // the next tick retries; nothing to do about a missed one
	}
}

// reportOnce sends one report if this node is a non-voter with a known remote
// leader. It reports whether a report was delivered.
func (a *appliedReporter) reportOnce(ctx context.Context) error {
	servers, err := a.node.Configuration()
	if err != nil {
		return err
	}
	nonvoter := false
	for _, s := range servers {
		if s.ID == a.nodeID && !s.Voter {
			nonvoter = true
		}
	}
	if !nonvoter {
		return nil
	}
	leaderID, leaderAddr := a.node.Leader()
	if leaderID == "" || leaderID == a.nodeID {
		return errors.New("no remote leader")
	}
	body, err := json.Marshal(map[string]any{"node_id": a.nodeID, "applied_index": a.node.AppliedIndex()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, //nolint:gosec // G704: the leader address comes from the Raft configuration, and the call is mutually authenticated
		"https://"+leaderAddr+"/v1/sys/storage/raft/report-applied", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.hc.Do(req) //nolint:gosec // G704: see above
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("leader answered %d", resp.StatusCode)
	}
	return nil
}
