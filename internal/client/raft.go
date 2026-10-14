package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RaftServer is one member in [RaftConfiguration].
type RaftServer struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	Leader  bool   `json:"leader"`
	Voter   bool   `json:"voter"`
}

// RaftConfiguration is sys/storage/raft/configuration.
type RaftConfiguration struct {
	Config struct {
		Servers []RaftServer `json:"servers"`
		Index   uint64       `json:"index"`
	} `json:"config"`
}

// RaftJoinRequest asks the connected (joining) node to join the cluster led by
// LeaderAPIAddr. LeaderCACert is the PEM of the CA that signed the leader's API
// certificate, or empty to use the node's system roots.
type RaftJoinRequest struct {
	LeaderAPIAddr string `json:"leader_api_addr"`
	LeaderCACert  string `json:"leader_ca_cert,omitempty"`
	JoinToken     string `json:"join_token"`
	Retry         bool   `json:"retry,omitempty"`
}

// RaftJoinResult is the outcome of [Client.RaftJoin].
type RaftJoinResult struct {
	Joined bool `json:"joined"`
	Retry  bool `json:"retry"`
}

// RaftJoin has the connected node join a cluster. The node must be a fresh,
// sealed one started with -raft-bootstrap=false.
func (c *Client) RaftJoin(ctx context.Context, req RaftJoinRequest) (*RaftJoinResult, error) {
	var out RaftJoinResult
	if err := c.do(ctx, http.MethodPost, "/v1/sys/storage/raft/join", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RaftJoinToken mints a single-use join token valid for ttl (0: the server's
// default). Requires sudo on the path.
func (c *Client) RaftJoinToken(ctx context.Context, ttl time.Duration) (token string, expires time.Time, err error) {
	body := map[string]string{}
	if ttl > 0 {
		body["ttl"] = ttl.String()
	}
	var out struct {
		JoinToken string    `json:"join_token"`
		Expires   time.Time `json:"expires"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/sys/storage/raft/join-token", body, &out); err != nil {
		return "", time.Time{}, err
	}
	return out.JoinToken, out.Expires, nil
}

// RaftConfiguration lists the cluster's members.
func (c *Client) RaftConfiguration(ctx context.Context) (*RaftConfiguration, error) {
	var out RaftConfiguration
	if err := c.do(ctx, http.MethodGet, "/v1/sys/storage/raft/configuration", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RaftRemovePeer removes a node from the cluster.
func (c *Client) RaftRemovePeer(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/sys/storage/raft/remove-peer", map[string]string{"server_id": id}, nil)
}

// RaftAutopilotServer is one entry of [RaftAutopilotState].
type RaftAutopilotServer struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	Status    string `json:"status"`
	Healthy   bool   `json:"healthy"`
	LastIndex uint64 `json:"last_index"`
	Voter     bool   `json:"voter"`
}

// RaftAutopilotState is sys/storage/raft/autopilot/state.
type RaftAutopilotState struct {
	Healthy          bool                           `json:"healthy"`
	FailureTolerance int                            `json:"failure_tolerance"`
	Leader           string                         `json:"leader"`
	Voters           []string                       `json:"voters"`
	Servers          map[string]RaftAutopilotServer `json:"servers"`
}

// RaftAutopilotState reports the cluster's health as the server sees it.
func (c *Client) RaftAutopilotState(ctx context.Context) (*RaftAutopilotState, error) {
	var out RaftAutopilotState
	if err := c.do(ctx, http.MethodGet, "/v1/sys/storage/raft/autopilot/state", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RaftSnapshotSave streams a snapshot of the cluster's state to w.
func (c *Client) RaftSnapshotSave(ctx context.Context, w io.Writer) error {
	resp, err := c.raw(ctx, http.MethodGet, "/v1/sys/storage/raft/snapshot", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("client: read snapshot: %w", err)
	}
	return nil
}

// RaftSnapshotRestore uploads a snapshot to replace the cluster's state. With
// force it is accepted even from a store with a different seal configuration.
func (c *Client) RaftSnapshotRestore(ctx context.Context, r io.Reader, force bool) error {
	path := "/v1/sys/storage/raft/snapshot"
	if force {
		path += "-force"
	}
	resp, err := c.raw(ctx, http.MethodPost, path, r)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// raw performs a request with an opaque body and returns a successful response
// for the caller to read; a non-2xx response becomes an [APIError].
func (c *Client) raw(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, body)
	if err != nil {
		return nil, fmt.Errorf("client: new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Errors: parseErrors(data)}
	}
	return resp, nil
}
