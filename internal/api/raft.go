package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/cluster"
	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

const (
	// maxRaftSnapshotBytes bounds an uploaded snapshot, which is buffered for
	// validation (the whole store, unlike the 1 MiB cap on other bodies).
	maxRaftSnapshotBytes = 1 << 30
)

// RaftNode is the part of the Raft backend the operator API drives.
type RaftNode interface {
	IsLeader() bool
	Leader() (id, addr string)
	Configuration() ([]raftstore.Server, error)
	MintJoinToken(ctx context.Context, ttl time.Duration) (string, time.Time, error)
	AcceptJoin(ctx context.Context, issuer raftstore.LeafIssuer, token, id, addr string) (*raftstore.Bridge, error)
	RemoveServer(id string) error
	ReportApplied(id string, index uint64)
	AppliedIndex() uint64
	Stats() raftstore.Stats
	WriteSnapshot(ctx context.Context, w io.Writer) error
	RestoreSnapshot(ctx context.Context, r io.Reader) error
}

// RaftJoinRequest is the joiner side of `operator raft join`: this node asks
// the leader at LeaderAPIAddr to admit it.
type RaftJoinRequest struct {
	LeaderAPIAddr string `json:"leader_api_addr"`
	LeaderCACert  string `json:"leader_ca_cert"`
	JoinToken     string `json:"join_token"`
	Retry         bool   `json:"retry"`
}

// RaftOptions wires the operator API (see [WithRaft]).
type RaftOptions struct {
	Node RaftNode
	// Issuer mints the bridge leaf handed to a joiner (cluster.Certs).
	Issuer raftstore.LeafIssuer
	// Join performs the joiner side: contact the leader, install the bridge
	// credential, and report whether the node is joined (false with Retry set
	// means it keeps trying in the background).
	Join func(ctx context.Context, req RaftJoinRequest) (joined bool, err error)
	// RotateCA replaces the cluster CA (cluster.Certs.Rotate). Active node only.
	RotateCA func(ctx context.Context) error
}

// WithRaft enables the sys/storage/raft/* endpoints over a Raft backend.
// Without it they answer 404-style "not enabled" errors.
func WithRaft(o RaftOptions) Option {
	return func(h *Handler) { h.raft = &o }
}

func (h *Handler) registerRaft(mux *http.ServeMux) {
	// join is the operator's call on the *joining* (sealed) node; join-accept is
	// that node's call on the leader and is authenticated by the join token
	// alone, as join is in Vault. report-applied is made by a joiner over the
	// cluster listener and is refused anywhere else.
	handleWrite(mux, "/v1/sys/storage/raft/join", h.raftEnabled(h.raftJoin))
	handleWrite(mux, "/v1/sys/storage/raft/join-accept", h.raftEnabled(h.raftJoinAccept))
	handleWrite(mux, "/v1/sys/storage/raft/report-applied", h.raftEnabled(h.raftReportApplied))

	handleWrite(mux, "/v1/sys/storage/raft/join-token", h.authenticate(h.raftEnabled(h.raftSudo(h.raftJoinToken))))
	mux.HandleFunc("GET /v1/sys/storage/raft/configuration", h.authenticate(h.raftEnabled(h.raftConfiguration)))
	handleWrite(mux, "/v1/sys/storage/raft/remove-peer", h.authenticate(h.raftEnabled(h.raftSudo(h.raftRemovePeer))))
	mux.HandleFunc("GET /v1/sys/storage/raft/snapshot", h.authenticate(h.raftEnabled(h.raftSnapshotSave)))
	handleWrite(mux, "/v1/sys/storage/raft/snapshot", h.authenticate(h.raftEnabled(h.raftSudo(h.raftSnapshotRestore(false)))))
	handleWrite(mux, "/v1/sys/storage/raft/snapshot-force", h.authenticate(h.raftEnabled(h.raftSudo(h.raftSnapshotRestore(true)))))
	handleWrite(mux, "/v1/sys/storage/raft/rotate-ca", h.authenticate(h.raftEnabled(h.raftSudo(h.raftRotateCA))))
	mux.HandleFunc("GET /v1/sys/storage/raft/autopilot/state", h.authenticate(h.raftEnabled(h.raftAutopilotState)))
}

func (h *Handler) raftEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.raft == nil {
			writeError(w, http.StatusBadRequest, "this vault is not using the raft storage backend")
			return
		}
		next(w, r)
	}
}

// raftSudo additionally requires the sudo capability on the request path.
func (h *Handler) raftSudo(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := tokenFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		sudo, err := h.hasSudo(r.Context(), tok, apiPath(r))
		if err != nil {
			writeInternal(w, err)
			return
		}
		if !sudo {
			writeError(w, http.StatusForbidden, "permission denied: this operation requires the sudo capability")
			return
		}
		next(w, r)
	}
}

// decodeBody reads a small JSON body into v; an empty body leaves v untouched.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	err := json.NewDecoder(r.Body).Decode(v)
	if err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// raftError maps a backend error to a status: a lost leadership is retryable,
// and every join-token failure is the same 403.
func raftError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrFenced):
		writeError(w, http.StatusServiceUnavailable, "this replica is not the Raft leader; retry")
	case errors.Is(err, raftstore.ErrTokenInvalid), errors.Is(err, raftstore.ErrTokenExpired), errors.Is(err, raftstore.ErrTokenUsed):
		// One answer for all three: do not tell a guesser which it was.
		writeError(w, http.StatusForbidden, "permission denied")
	default:
		writeInternal(w, err)
	}
}

type raftJoinResponse struct {
	Joined bool `json:"joined"`
	Retry  bool `json:"retry,omitempty"`
}

// raftJoin is `operator raft join` on the node that is joining.
func (h *Handler) raftJoin(w http.ResponseWriter, r *http.Request) {
	var req RaftJoinRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.LeaderAPIAddr == "" || req.JoinToken == "" {
		writeError(w, http.StatusBadRequest, "leader_api_addr and join_token are required")
		return
	}
	if h.raft.Join == nil {
		writeError(w, http.StatusBadRequest, "this node cannot join a cluster")
		return
	}
	joined, err := h.raft.Join(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "join failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, raftJoinResponse{Joined: joined, Retry: !joined && req.Retry})
}

type raftJoinAcceptRequest struct {
	JoinToken string `json:"join_token"`
	NodeID    string `json:"node_id"`
	Address   string `json:"address"`
}

type raftJoinAcceptResponse struct {
	CACert   string    `json:"ca_cert"`
	Cert     string    `json:"cert"`
	Key      string    `json:"key"`
	NotAfter time.Time `json:"not_after"`
}

// raftJoinAccept is the leader side of a join: it verifies and burns the token
// and returns the bridge credential.
func (h *Handler) raftJoinAccept(w http.ResponseWriter, r *http.Request) {
	var req raftJoinAcceptRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.JoinToken == "" || req.NodeID == "" || req.Address == "" {
		writeError(w, http.StatusBadRequest, "join_token, node_id and address are required")
		return
	}
	b, err := h.raft.Node.AcceptJoin(r.Context(), h.raft.Issuer, req.JoinToken, req.NodeID, req.Address)
	if err != nil {
		raftError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, raftJoinAcceptResponse{
		CACert: string(b.CAPEM), Cert: string(b.CertPEM), Key: string(b.KeyPEM), NotAfter: b.NotAfter,
	})
}

type raftReportRequest struct {
	NodeID       string `json:"node_id"`
	AppliedIndex uint64 `json:"applied_index"`
}

// raftReportApplied records a non-voter's applied index for promotion. It is
// served only to a peer on the cluster listener (mutual TLS under the cluster
// CA); on the public API it is refused, so a client cannot nudge a promotion.
func (h *Handler) raftReportApplied(w http.ResponseWriter, r *http.Request) {
	if !cluster.DirectPeer(r) {
		writeError(w, http.StatusForbidden, "permission denied")
		return
	}
	var req raftReportRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.NodeID == "" {
		writeError(w, http.StatusBadRequest, "node_id is required")
		return
	}
	h.raft.Node.ReportApplied(req.NodeID, req.AppliedIndex)
	w.WriteHeader(http.StatusNoContent)
}

type raftJoinTokenRequest struct {
	TTL string `json:"ttl"`
}

type raftJoinTokenResponse struct {
	JoinToken string    `json:"join_token"`
	Expires   time.Time `json:"expires"`
}

func (h *Handler) raftJoinToken(w http.ResponseWriter, r *http.Request) {
	var req raftJoinTokenRequest
	if !decodeBody(w, r, &req) {
		return
	}
	var ttl time.Duration
	if req.TTL != "" {
		d, err := time.ParseDuration(secondsIfBare(req.TTL))
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "ttl must be a positive duration")
			return
		}
		ttl = d
	}
	tok, exp, err := h.raft.Node.MintJoinToken(r.Context(), ttl)
	if err != nil {
		raftError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, raftJoinTokenResponse{JoinToken: tok, Expires: exp})
}

type raftServer struct {
	NodeID          string `json:"node_id"`
	Address         string `json:"address"`
	Leader          bool   `json:"leader"`
	ProtocolVersion string `json:"protocol_version"`
	Voter           bool   `json:"voter"`
}

type raftConfig struct {
	Servers []raftServer `json:"servers"`
	Index   uint64       `json:"index"`
}

// raftConfigData is Vault's shape: the configuration under "data".
type raftConfigData struct {
	Config raftConfig `json:"config"`
}

// raftConfigResponse answers with Vault's {"data":{"config":...}} envelope,
// which the Vault CLI's `operator raft list-peers` expects. The top-level
// "config" is the pre-1.6.0 shape, kept so older ubixvault clients (and
// internal/client) keep working; Vault clients ignore it.
type raftConfigResponse struct {
	Data   raftConfigData `json:"data"`
	Config raftConfig     `json:"config"`
}

// raftServers lists the configuration with the leader flagged.
func (h *Handler) raftServers() ([]raftServer, error) {
	cfg, err := h.raft.Node.Configuration()
	if err != nil {
		return nil, err
	}
	leaderID, _ := h.raft.Node.Leader()
	out := make([]raftServer, 0, len(cfg))
	for _, s := range cfg {
		out = append(out, raftServer{
			NodeID: s.ID, Address: s.Address, Leader: s.ID == leaderID,
			ProtocolVersion: "3", Voter: s.Voter,
		})
	}
	return out, nil
}

func (h *Handler) raftConfiguration(w http.ResponseWriter, _ *http.Request) {
	servers, err := h.raftServers()
	if err != nil {
		writeInternal(w, err)
		return
	}
	cfg := raftConfig{Servers: servers, Index: h.raft.Node.Stats().LastIndex}
	resp := raftConfigResponse{Data: raftConfigData{Config: cfg}, Config: cfg}
	writeJSON(w, http.StatusOK, resp)
}

type raftRemoveRequest struct {
	ServerID string `json:"server_id"`
}

// raftRemovePeer removes a node. It refuses a removal that would leave the
// remaining voters unable to elect, and the leader itself (step down first).
func (h *Handler) raftRemovePeer(w http.ResponseWriter, r *http.Request) {
	var req raftRemoveRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ServerID == "" {
		writeError(w, http.StatusBadRequest, "server_id is required")
		return
	}
	servers, err := h.raft.Node.Configuration()
	if err != nil {
		writeInternal(w, err)
		return
	}
	leaderID, _ := h.raft.Node.Leader()
	var target *raftstore.Server
	voters := 0
	for i := range servers {
		if servers[i].ID == req.ServerID {
			target = &servers[i]
		}
		if servers[i].Voter {
			voters++
		}
	}
	switch {
	case target == nil:
		writeError(w, http.StatusNotFound, "no such server in the Raft configuration")
		return
	case target.ID == leaderID:
		writeError(w, http.StatusBadRequest, "cannot remove the leader; step it down first (sys/step-down)")
		return
	case target.Voter && voters-1 < 1:
		writeError(w, http.StatusBadRequest, "cannot remove the last voter")
		return
	}
	if err := h.raft.Node.RemoveServer(req.ServerID); err != nil {
		raftError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) raftSnapshotSave(w http.ResponseWriter, r *http.Request) {
	// Buffer first: a failure after the first byte could only truncate the
	// stream, and a truncated backup that looks complete is worse than an error.
	var buf bytes.Buffer
	if err := h.raft.Node.WriteSnapshot(r.Context(), &buf); err != nil {
		writeInternal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="ubixvault.snapshot"`)
	_, _ = w.Write(buf.Bytes())
}

// raftSnapshotRestore replaces the cluster's state with the uploaded snapshot.
// Unless force is set it refuses a snapshot from a differently-keyed store
// (see sameStore), because after it the current unseal keys would no longer
// open the vault.
func (h *Handler) raftSnapshotRestore(force bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.raft.Node.IsLeader() {
			writeError(w, http.StatusServiceUnavailable, "this replica is not the Raft leader; retry")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRaftSnapshotBytes)
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read the snapshot (is it larger than 1 GiB?)")
			return
		}
		if !force {
			ok, err := h.sameStore(r.Context(), data)
			if err != nil {
				writeError(w, http.StatusBadRequest, "snapshot is not valid: "+err.Error())
				return
			}
			if !ok {
				writeError(w, http.StatusConflict,
					"snapshot comes from a store with a different seal configuration; restoring it would change the unseal keys. Use snapshot-force if that is intended")
				return
			}
		}
		if err := h.raft.Node.RestoreSnapshot(r.Context(), bytes.NewReader(data)); err != nil {
			raftError(w, err)
			return
		}
		h.resetBarrierCaches()
		w.WriteHeader(http.StatusNoContent)
	}
}

// sealConfigKey is the barrier's seal configuration entry; it is present in
// every snapshot of an initialized store.
const sealConfigKey = "core/seal-config"

// sameStore reports whether the snapshot's seal configuration equals this
// store's. It is the "does this snapshot belong to this cluster" check:
// snapshots carry no cluster ID, and a restore from another initialized vault
// (or from before a rekey) would leave the running keys unable to open it.
// Both sides being uninitialized counts as the same.
func (h *Handler) sameStore(ctx context.Context, snap []byte) (bool, error) {
	scratch := storage.NewMemoryBackend()
	if err := snapshot.Restore(ctx, scratch, bytes.NewReader(snap)); err != nil {
		return false, err
	}
	theirs, err := scratch.Get(ctx, sealConfigKey)
	if err != nil {
		return false, err
	}
	ours, err := h.core.SealConfigRaw(ctx)
	if err != nil {
		return false, err
	}
	switch {
	case theirs == nil && ours == nil:
		return true, nil
	case theirs == nil || ours == nil:
		return false, nil
	}
	return bytes.Equal(theirs.Value, ours), nil
}

type raftAutopilotServer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	NodeStatus  string `json:"node_status"`
	Status      string `json:"status"`
	Healthy     bool   `json:"healthy"`
	LastIndex   uint64 `json:"last_index,omitempty"`
	LastContact string `json:"last_contact,omitempty"`
	Voter       bool   `json:"voter"`
}

type raftAutopilotState struct {
	Healthy          bool                           `json:"healthy"`
	FailureTolerance int                            `json:"failure_tolerance"`
	Leader           string                         `json:"leader"`
	Voters           []string                       `json:"voters"`
	Servers          map[string]raftAutopilotServer `json:"servers"`
}

// raftAutopilotResponse carries the state under Vault's "data" and, for older
// clients, at the top level (embedded); see [raftConfigResponse].
type raftAutopilotResponse struct {
	raftAutopilotState
	Data raftAutopilotState `json:"data"`
}

// raftAutopilotState is a subset of Vault's autopilot state, from what this
// node knows: membership and who leads. Per-server last_index/last_contact
// are not available (the consensus library does not expose follower progress),
// so they are omitted rather than invented.
func (h *Handler) raftAutopilotState(w http.ResponseWriter, _ *http.Request) {
	servers, err := h.raftServers()
	if err != nil {
		writeInternal(w, err)
		return
	}
	leaderID, _ := h.raft.Node.Leader()
	resp := raftAutopilotState{
		Healthy: leaderID != "", Leader: leaderID, Voters: []string{},
		Servers: map[string]raftAutopilotServer{},
	}
	nVoters := 0
	for _, s := range servers {
		status := "non-voter"
		if s.Voter {
			status = "voter"
			nVoters++
			resp.Voters = append(resp.Voters, s.NodeID)
		}
		if s.Leader {
			status = "leader"
		}
		resp.Servers[s.NodeID] = raftAutopilotServer{
			ID: s.NodeID, Name: s.NodeID, Address: s.Address,
			NodeStatus: "alive", Status: status, Healthy: leaderID != "", Voter: s.Voter,
		}
	}
	resp.FailureTolerance = max(0, (nVoters-1)/2)
	if st := h.raft.Node.Stats(); st.Leader {
		sv := resp.Servers[leaderID]
		sv.LastIndex = st.LastIndex
		resp.Servers[leaderID] = sv
	}
	writeJSON(w, http.StatusOK, raftAutopilotResponse{raftAutopilotState: resp, Data: resp})
}

// raftRotateCA replaces the cluster CA on the leader. The other nodes lose the
// cluster transport until they are re-seated, which the operator does next.
func (h *Handler) raftRotateCA(w http.ResponseWriter, r *http.Request) {
	if h.raft.RotateCA == nil || !h.raft.Node.IsLeader() {
		writeError(w, http.StatusServiceUnavailable, "rotate the cluster CA on the Raft leader")
		return
	}
	if err := h.raft.RotateCA(r.Context()); err != nil {
		raftError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
