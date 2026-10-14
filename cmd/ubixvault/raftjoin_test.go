package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/api"
	raftstore "github.com/cwolsen7905/ubixvault/internal/storage/raft"
)

type fakeInstaller struct {
	ca, cert, key []byte
	err           error
}

func (f *fakeInstaller) SetBridge(ca, cert, key []byte) error {
	f.ca, f.cert, f.key = ca, cert, key
	return f.err
}

type fakeNode struct {
	servers  []raftstore.Server
	leaderID string
	leader   string
	applied  uint64
}

func (n *fakeNode) Configuration() ([]raftstore.Server, error) { return n.servers, nil }
func (n *fakeNode) Leader() (string, string)                   { return n.leaderID, n.leader }
func (n *fakeNode) AppliedIndex() uint64                       { return n.applied }

// fakeLeader is a TLS leader API answering join-accept.
func fakeLeader(t *testing.T, status int, calls *atomic.Int32, gotBody *string) (addr, caPEM string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/sys/storage/raft/join-accept" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		if gotBody != nil {
			b, _ := json.Marshal(m)
			*gotBody = string(b)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"ca_cert":"CA","cert":"CERT","key":"KEY"}`))
			return
		}
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	t.Cleanup(srv.Close)
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return srv.URL, caPEM
}

func TestJoinerOnceInstallsBridge(t *testing.T) {
	var calls atomic.Int32
	var body string
	addr, ca := fakeLeader(t, http.StatusOK, &calls, &body)
	inst := &fakeInstaller{}
	j := &raftJoiner{nodeID: "n2", advertise: "n2:8201", certs: inst, node: &fakeNode{}}

	if err := j.once(context.Background(), addr, ca, "ubxj.secret"); err != nil {
		t.Fatalf("once: %v", err)
	}
	if string(inst.ca) != "CA" || string(inst.cert) != "CERT" || string(inst.key) != "KEY" {
		t.Fatalf("installed %q %q %q", inst.ca, inst.cert, inst.key)
	}
	for _, want := range []string{`"node_id":"n2"`, `"address":"n2:8201"`, `"join_token":"ubxj.secret"`} {
		if !strings.Contains(body, want) {
			t.Errorf("request %s lacks %s", body, want)
		}
	}
}

func TestJoinerPinsLeaderCA(t *testing.T) {
	var calls atomic.Int32
	addr, _ := fakeLeader(t, http.StatusOK, &calls, nil)
	j := &raftJoiner{nodeID: "n2", advertise: "n2:8201", certs: &fakeInstaller{}, node: &fakeNode{}}

	// Without the leader's CA (system roots) the handshake must fail, and the
	// token must not have been sent.
	if err := j.once(context.Background(), addr, "", "ubxj.secret"); err == nil {
		t.Fatal("join succeeded against an untrusted leader certificate")
	}
	if calls.Load() != 0 {
		t.Fatal("token was sent to an unverified leader")
	}
	if err := j.once(context.Background(), addr, "not pem", "t"); err == nil {
		t.Fatal("garbage CA accepted")
	}
}

func TestJoinerErrorNeverContainsToken(t *testing.T) {
	var calls atomic.Int32
	addr, ca := fakeLeader(t, http.StatusForbidden, &calls, nil)
	j := &raftJoiner{nodeID: "n2", advertise: "n2:8201", certs: &fakeInstaller{}, node: &fakeNode{}}
	err := j.once(context.Background(), addr, ca, "ubxj.SECRETVALUE")
	if err == nil || strings.Contains(err.Error(), "SECRETVALUE") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestJoinerRetryBacksOffUntilJoined(t *testing.T) {
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusForbidden)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(`{"ca_cert":"CA","cert":"C","key":"K","errors":["no"]}`))
	}))
	t.Cleanup(srv.Close)
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	inst := &fakeInstaller{}
	j := &raftJoiner{
		nodeID: "n2", advertise: "n2:8201", certs: inst, node: &fakeNode{},
		backoffMin: 5 * time.Millisecond, backoffMax: 20 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		j.retry(context.Background(), []string{"https://127.0.0.1:1", srv.URL}, ca, func() (string, error) { return "t", nil })
	}()
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("no retries")
		}
		time.Sleep(5 * time.Millisecond)
	}
	status.Store(http.StatusOK)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("retry did not stop after a successful join")
	}
	if string(inst.cert) != "C" {
		t.Fatalf("bridge not installed: %q", inst.cert)
	}
}

func TestJoinerRetryStopsWhenAlreadyMember(t *testing.T) {
	j := &raftJoiner{
		nodeID: "n2", certs: &fakeInstaller{},
		node: &fakeNode{servers: []raftstore.Server{{ID: "n2"}}},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		j.retry(context.Background(), []string{"https://127.0.0.1:1"}, "", func() (string, error) {
			t.Error("token requested although already a member")
			return "", errors.New("unused")
		})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop kept going for a member")
	}
}

func TestJoinerRetryStopsOnContext(t *testing.T) {
	j := &raftJoiner{nodeID: "n2", certs: &fakeInstaller{}, node: &fakeNode{}, backoffMin: time.Hour, backoffMax: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		j.retry(ctx, []string{"https://127.0.0.1:1"}, "", func() (string, error) { return "t", nil })
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry ignored context cancellation")
	}
}

func TestJoinerJoinForMemberAndRetryRequest(t *testing.T) {
	j := &raftJoiner{
		nodeID: "n2", certs: &fakeInstaller{},
		node: &fakeNode{servers: []raftstore.Server{{ID: "n2"}}},
	}
	joined, err := j.Join(context.Background(), api.RaftJoinRequest{LeaderAPIAddr: "x", JoinToken: "t"})
	if err != nil || !joined {
		t.Fatalf("Join for a member = %v, %v", joined, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	j2 := &raftJoiner{nodeID: "n3", certs: &fakeInstaller{}, node: &fakeNode{}, ctx: ctx, backoffMin: time.Hour}
	joined, err = j2.Join(context.Background(), api.RaftJoinRequest{LeaderAPIAddr: "https://127.0.0.1:1", JoinToken: "t", Retry: true})
	if err != nil || joined {
		t.Fatalf("retrying Join = %v, %v; want not-yet-joined without error", joined, err)
	}
}

func TestTokenSource(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tok")
	if err := os.WriteFile(f, []byte("  ubxj.fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := tokenSource(f)(); err != nil || got != "ubxj.fromfile" {
		t.Fatalf("file token = %q, %v", got, err)
	}
	if err := os.WriteFile(f, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tokenSource(f)(); err == nil {
		t.Fatal("empty token file accepted")
	}
	t.Setenv("UBIXVAULT_RAFT_JOIN_TOKEN", "ubxj.fromenv")
	if got, err := tokenSource("")(); err != nil || got != "ubxj.fromenv" {
		t.Fatalf("env token = %q, %v", got, err)
	}
	t.Setenv("UBIXVAULT_RAFT_JOIN_TOKEN", "")
	if _, err := tokenSource("")(); err == nil {
		t.Fatal("missing token accepted")
	}
}

func TestAppliedReporter(t *testing.T) {
	var got struct {
		path string
		body map[string]any
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "https://")

	hc := srv.Client()

	n := &fakeNode{
		servers:  []raftstore.Server{{ID: "l", Voter: true}, {ID: "me"}},
		leaderID: "l", leader: host, applied: 123,
	}
	r := &appliedReporter{nodeID: "me", node: n, hc: hc}
	if err := r.reportOnce(context.Background()); err != nil {
		t.Fatalf("reportOnce: %v", err)
	}
	if got.path != "/v1/sys/storage/raft/report-applied" || got.body["node_id"] != "me" || got.body["applied_index"] != float64(123) {
		t.Fatalf("report = %+v", got)
	}

	// A voter has nothing to report.
	got.path = ""
	n.servers = []raftstore.Server{{ID: "l", Voter: true}, {ID: "me", Voter: true}}
	if err := r.reportOnce(context.Background()); err != nil || got.path != "" {
		t.Fatalf("voter reported: %v %q", err, got.path)
	}

	// No remote leader: an error, and nothing sent.
	n.servers = []raftstore.Server{{ID: "l", Voter: true}, {ID: "me"}}
	n.leaderID = ""
	if err := r.reportOnce(context.Background()); err == nil || got.path != "" {
		t.Fatalf("no leader: %v %q", err, got.path)
	}
}
