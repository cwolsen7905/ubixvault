package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/cluster"
	"github.com/cwolsen7905/ubixvault/internal/core"
	"github.com/cwolsen7905/ubixvault/internal/snapshot"
	"github.com/cwolsen7905/ubixvault/internal/storage"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

type fakeRaft struct {
	leader   bool
	leaderID string
	servers  []raftstore.Server
	removed  []string
	reports  map[string]uint64
	joinErr  error
	accepted []string
	restored []byte
	minted   time.Duration
}

func (f *fakeRaft) IsLeader() bool                             { return f.leader }
func (f *fakeRaft) Leader() (string, string)                   { return f.leaderID, "" }
func (f *fakeRaft) Configuration() ([]raftstore.Server, error) { return f.servers, nil }
func (f *fakeRaft) RemoveServer(id string) error               { f.removed = append(f.removed, id); return nil }
func (f *fakeRaft) AppliedIndex() uint64                       { return 7 }
func (f *fakeRaft) Stats() raftstore.Stats                     { return raftstore.Stats{LastIndex: 42, Leader: f.leader} }
func (f *fakeRaft) WriteSnapshot(_ context.Context, w io.Writer) error {
	_, err := w.Write([]byte("snap"))
	return err
}
func (f *fakeRaft) RestoreSnapshot(_ context.Context, r io.Reader) error {
	b, err := io.ReadAll(r)
	f.restored = b
	return err
}
func (f *fakeRaft) ReportApplied(id string, idx uint64) {
	if f.reports == nil {
		f.reports = map[string]uint64{}
	}
	f.reports[id] = idx
}
func (f *fakeRaft) MintJoinToken(_ context.Context, ttl time.Duration) (string, time.Time, error) {
	f.minted = ttl
	return "ubxj.test", time.Unix(1700000000, 0), nil
}
func (f *fakeRaft) AcceptJoin(_ context.Context, _ raftstore.LeafIssuer, token, id, addr string) (*raftstore.Bridge, error) {
	if f.joinErr != nil {
		return nil, f.joinErr
	}
	f.accepted = append(f.accepted, token+"|"+id+"|"+addr)
	return &raftstore.Bridge{CAPEM: []byte("ca"), CertPEM: []byte("cert"), KeyPEM: []byte("key")}, nil
}

func raftHandler(t *testing.T, f *fakeRaft, join func(context.Context, RaftJoinRequest) (bool, error)) (http.Handler, string) {
	t.Helper()
	h := NewHandler(core.New(storage.NewMemoryBackend()), WithRaft(RaftOptions{Node: f, Join: join}))
	init := decode[initResponse](t, do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`))
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[0]+`"}`)
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[1]+`"}`)
	return h, init.RootToken
}

func TestRaftEndpointsDisabledWithoutRaft(t *testing.T) {
	h, root := unsealedHandler(t)
	for _, p := range []string{"configuration", "autopilot/state"} {
		if rec := doAuth(t, h, "GET", "/v1/sys/storage/raft/"+p, "", root); rec.Code != http.StatusBadRequest {
			t.Errorf("%s without raft = %d, want 400", p, rec.Code)
		}
	}
}

func TestRaftOperatorEndpointsNeedToken(t *testing.T) {
	h, _ := raftHandler(t, &fakeRaft{leader: true}, nil)
	for _, c := range [][2]string{
		{"GET", "configuration"}, {"POST", "join-token"}, {"POST", "remove-peer"}, {"POST", "rotate-ca"},
		{"GET", "snapshot"}, {"POST", "snapshot"}, {"POST", "snapshot-force"}, {"GET", "autopilot/state"},
	} {
		if rec := do(t, h, c[0], "/v1/sys/storage/raft/"+c[1], `{}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token = %d, want 401", c[0], c[1], rec.Code)
		}
	}
}

func TestRaftConfigurationAndAutopilot(t *testing.T) {
	f := &fakeRaft{leader: true, leaderID: "a", servers: []raftstore.Server{
		{ID: "a", Address: "a:8201", Voter: true},
		{ID: "b", Address: "b:8201", Voter: true},
		{ID: "c", Address: "c:8201"},
	}}
	h, root := raftHandler(t, f, nil)

	cfg := decode[raftConfigResponse](t, doAuth(t, h, "GET", "/v1/sys/storage/raft/configuration", "", root))
	if len(cfg.Data.Config.Servers) != 3 || !cfg.Data.Config.Servers[0].Leader || cfg.Data.Config.Servers[1].Leader || cfg.Data.Config.Servers[2].Voter || cfg.Data.Config.Index != 42 {
		t.Fatalf("configuration = %+v", cfg)
	}
	if len(cfg.Config.Servers) != 3 {
		t.Fatalf("legacy top-level config missing: %+v", cfg)
	}
	st := decode[raftAutopilotResponse](t, doAuth(t, h, "GET", "/v1/sys/storage/raft/autopilot/state", "", root))
	if st.Data.Leader != "a" || !st.Data.Healthy {
		t.Fatalf("autopilot data envelope = %+v", st)
	}
	if !st.Healthy || st.Leader != "a" || len(st.Voters) != 2 || st.FailureTolerance != 0 || st.Servers["c"].Status != "non-voter" || st.Servers["a"].Status != "leader" {
		t.Fatalf("autopilot = %+v", st)
	}
}

func TestRaftRemovePeer(t *testing.T) {
	f := &fakeRaft{leader: true, leaderID: "a", servers: []raftstore.Server{
		{ID: "a", Voter: true}, {ID: "b", Voter: true}, {ID: "c"},
	}}
	h, root := raftHandler(t, f, nil)
	post := func(id string) int {
		return doAuth(t, h, "POST", "/v1/sys/storage/raft/remove-peer", `{"server_id":"`+id+`"}`, root).Code
	}
	if c := post("a"); c != http.StatusBadRequest {
		t.Errorf("remove leader = %d, want 400", c)
	}
	if c := post("zz"); c != http.StatusNotFound {
		t.Errorf("remove unknown = %d, want 404", c)
	}
	if c := post("c"); c != http.StatusNoContent {
		t.Errorf("remove non-voter = %d, want 204", c)
	}
	if len(f.removed) != 1 || f.removed[0] != "c" {
		t.Fatalf("removed = %v", f.removed)
	}
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/remove-peer", `{}`, root).Code; c != http.StatusBadRequest {
		t.Errorf("empty server_id = %d, want 400", c)
	}
}

func TestRaftSudoRequired(t *testing.T) {
	h, root := raftHandler(t, &fakeRaft{leader: true}, nil)
	// A policy that can write the paths but without sudo.
	pol := `{"policy":"path \"sys/storage/raft/*\" { capabilities = [\"create\",\"read\",\"update\"] }"}`
	if rec := doAuth(t, h, "PUT", "/v1/sys/policies/acl/raftops", pol, root); rec.Code >= 300 {
		t.Fatalf("policy write = %d %s", rec.Code, rec.Body.String())
	}
	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["raftops"]}`, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("token create = %d %s", rec.Code, rec.Body.String())
	}
	tok := decode[map[string]any](t, rec)["auth"].(map[string]any)["client_token"].(string)
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/join-token", `{}`, tok).Code; c != http.StatusForbidden {
		t.Errorf("join-token without sudo = %d, want 403", c)
	}
	if c := doAuth(t, h, "GET", "/v1/sys/storage/raft/configuration", ``, tok).Code; c != http.StatusOK {
		t.Errorf("configuration with read = %d, want allowed", c)
	}
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/join-token", `{}`, root).Code; c != http.StatusOK {
		t.Errorf("join-token as root = %d, want 200", c)
	}
}

func TestRaftJoinToken(t *testing.T) {
	f := &fakeRaft{leader: true}
	h, root := raftHandler(t, f, nil)
	rec := doAuth(t, h, "POST", "/v1/sys/storage/raft/join-token", `{"ttl":"30m"}`, root)
	if rec.Code != http.StatusOK || f.minted != 30*time.Minute || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("join-token = %d ttl=%v hdr=%q", rec.Code, f.minted, rec.Header().Get("Cache-Control"))
	}
	if got := decode[raftJoinTokenResponse](t, rec).JoinToken; got != "ubxj.test" {
		t.Fatalf("token = %q", got)
	}
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/join-token", `{"ttl":"-1m"}`, root).Code; c != http.StatusBadRequest {
		t.Errorf("negative ttl = %d, want 400", c)
	}
}

func TestRaftJoinAcceptIsTokenAuthenticatedAndUniform(t *testing.T) {
	f := &fakeRaft{leader: true}
	h, _ := raftHandler(t, f, nil)
	body := `{"join_token":"ubxj.x","node_id":"n1","address":"n1:8201"}`
	rec := do(t, h, "POST", "/v1/sys/storage/raft/join-accept", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("join-accept = %d %s", rec.Code, rec.Body.String())
	}
	if len(f.accepted) != 1 || f.accepted[0] != "ubxj.x|n1|n1:8201" {
		t.Fatalf("accepted = %v", f.accepted)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("bridge credential response is cacheable")
	}
	// The three token failures are indistinguishable to the caller.
	for _, e := range []error{raftstore.ErrTokenInvalid, raftstore.ErrTokenExpired, raftstore.ErrTokenUsed} {
		f.joinErr = e
		rec := do(t, h, "POST", "/v1/sys/storage/raft/join-accept", body)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "used") || strings.Contains(rec.Body.String(), "expired") {
			t.Errorf("%v → %d %s", e, rec.Code, rec.Body.String())
		}
	}
	f.joinErr = storage.ErrFenced
	if c := do(t, h, "POST", "/v1/sys/storage/raft/join-accept", body).Code; c != http.StatusServiceUnavailable {
		t.Errorf("not leader = %d, want 503", c)
	}
	if c := do(t, h, "POST", "/v1/sys/storage/raft/join-accept", `{"join_token":"x"}`).Code; c != http.StatusBadRequest {
		t.Errorf("incomplete = %d, want 400", c)
	}
}

func TestRaftReportAppliedOnlyFromDirectPeer(t *testing.T) {
	f := &fakeRaft{leader: true}
	h, _ := raftHandler(t, f, nil)
	body := `{"node_id":"n1","applied_index":99}`

	// The public API refuses it outright.
	if c := do(t, h, "POST", "/v1/sys/storage/raft/report-applied", body).Code; c != http.StatusForbidden {
		t.Fatalf("public report-applied = %d, want 403", c)
	}
	peer := cluster.ServerHandler(h, func() bool { return true })

	// A request a standby forwarded for a client carries the client address.
	req := httptest.NewRequest("POST", "/v1/sys/storage/raft/report-applied", strings.NewReader(body))
	req.Header.Set("X-Ubixvault-Cluster-Client-Addr", "203.0.113.9:1234")
	rec := httptest.NewRecorder()
	peer.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || len(f.reports) != 0 {
		t.Fatalf("forwarded report-applied = %d reports=%v, want 403 and none", rec.Code, f.reports)
	}

	// A peer speaking for itself is accepted.
	req = httptest.NewRequest("POST", "/v1/sys/storage/raft/report-applied", strings.NewReader(body))
	rec = httptest.NewRecorder()
	peer.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || f.reports["n1"] != 99 {
		t.Fatalf("direct report-applied = %d reports=%v", rec.Code, f.reports)
	}
}

func TestRaftJoinOperatorCall(t *testing.T) {
	var got RaftJoinRequest
	var joined bool
	var jerr error
	h, _ := raftHandler(t, &fakeRaft{}, func(_ context.Context, r RaftJoinRequest) (bool, error) {
		got = r
		return joined, jerr
	})
	body := `{"leader_api_addr":"https://l:8200","join_token":"ubxj.t","retry":true}`

	rec := do(t, h, "POST", "/v1/sys/storage/raft/join", body)
	if rec.Code != http.StatusOK || got.LeaderAPIAddr != "https://l:8200" || !got.Retry {
		t.Fatalf("join = %d %s got=%+v", rec.Code, rec.Body.String(), got)
	}
	if r := decode[raftJoinResponse](t, rec); r.Joined || !r.Retry {
		t.Fatalf("response = %+v, want retrying", r)
	}
	joined = true
	if r := decode[raftJoinResponse](t, do(t, h, "PUT", "/v1/sys/storage/raft/join", body)); !r.Joined {
		t.Fatalf("response = %+v, want joined", r)
	}
	jerr = errors.New("boom")
	if c := do(t, h, "POST", "/v1/sys/storage/raft/join", body).Code; c != http.StatusBadGateway {
		t.Errorf("failed join = %d, want 502", c)
	}
	if c := do(t, h, "POST", "/v1/sys/storage/raft/join", `{"leader_api_addr":"x"}`).Code; c != http.StatusBadRequest {
		t.Errorf("missing token = %d, want 400", c)
	}
}

func snapshotWith(t *testing.T, sealConfig string) []byte {
	t.Helper()
	m := storage.NewMemoryBackend()
	if sealConfig != "" {
		if err := m.Put(context.Background(), &storage.Entry{Key: "core/seal-config", Value: []byte(sealConfig)}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := snapshot.Write(context.Background(), m, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRaftSnapshotSaveAndRestore(t *testing.T) {
	f := &fakeRaft{leader: true}
	h, root := raftHandler(t, f, nil)

	rec := doAuth(t, h, "GET", "/v1/sys/storage/raft/snapshot", "", root)
	if rec.Code != http.StatusOK || rec.Body.String() != "snap" {
		t.Fatalf("save = %d %q", rec.Code, rec.Body.String())
	}

	foreign := snapshotWith(t, `{"other":"cluster"}`)
	rec = doAuth(t, h, "POST", "/v1/sys/storage/raft/snapshot", string(foreign), root)
	if rec.Code != http.StatusConflict || f.restored != nil {
		t.Fatalf("foreign restore = %d restored=%v, want 409 and untouched", rec.Code, f.restored != nil)
	}
	rec = doAuth(t, h, "POST", "/v1/sys/storage/raft/snapshot-force", string(foreign), root)
	if rec.Code != http.StatusNoContent || !bytes.Equal(f.restored, foreign) {
		t.Fatalf("forced restore = %d", rec.Code)
	}

	// Garbage is a 400 either way, never reaches the backend.
	f.restored = nil
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/snapshot", "not a snapshot", root).Code; c != http.StatusBadRequest {
		t.Errorf("garbage restore = %d, want 400", c)
	}
	if f.restored != nil {
		t.Error("garbage snapshot reached the backend")
	}

	f.leader = false
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/snapshot-force", string(foreign), root).Code; c != http.StatusServiceUnavailable {
		t.Errorf("restore on non-leader = %d, want 503", c)
	}
}

func TestRaftJoinEndpointServedByStandby(t *testing.T) {
	if !standbyEndpoint("/v1/sys/storage/raft/join") {
		t.Error("join must be served locally by a sealed standby")
	}
	for _, p := range []string{"join-accept", "report-applied", "join-token", "configuration"} {
		if standbyEndpoint("/v1/sys/storage/raft/" + p) {
			t.Errorf("%s must be forwarded to the active replica", p)
		}
	}
}

func TestRaftRotateCA(t *testing.T) {
	rotations := 0
	f := &fakeRaft{leader: true}
	h := NewHandler(core.New(storage.NewMemoryBackend()), WithRaft(RaftOptions{
		Node: f, RotateCA: func(context.Context) error { rotations++; return nil },
	}))
	init := decode[initResponse](t, do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`))
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[0]+`"}`)
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[1]+`"}`)
	root := init.RootToken

	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/rotate-ca", `{}`, root).Code; c != http.StatusNoContent {
		t.Fatalf("rotate-ca = %d, want 204", c)
	}
	if rotations != 1 {
		t.Fatalf("rotations = %d", rotations)
	}
	f.leader = false
	if c := doAuth(t, h, "POST", "/v1/sys/storage/raft/rotate-ca", `{}`, root).Code; c != http.StatusServiceUnavailable {
		t.Errorf("rotate-ca on a follower = %d, want 503", c)
	}
	if rotations != 1 {
		t.Fatalf("a follower rotated the CA")
	}
}
