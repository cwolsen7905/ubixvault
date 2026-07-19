package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwolsen7905/ubixvault/internal/audit"
	"github.com/cwolsen7905/ubixvault/internal/core"
	"github.com/cwolsen7905/ubixvault/internal/storage"
)

// auditedHandler returns an unsealed handler whose requests are audited to a
// file, plus the root token and the log path.
func auditedHandler(t *testing.T) (*Handler, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	device, err := audit.NewFileDevice(path)
	if err != nil {
		t.Fatalf("NewFileDevice: %v", err)
	}
	c := core.New(storage.NewMemoryBackend())
	h := NewHandler(c, WithAudit(audit.NewBroker(device)))

	init := decode[initResponse](t, do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`))
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[0]+`"}`)
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[1]+`"}`)
	return h, init.RootToken, path
}

func auditLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: test path from t.TempDir()
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func TestAuditLogsRequestAndResponse(t *testing.T) {
	h, root, path := auditedHandler(t)

	doAuth(t, h, "POST", "/v1/secret/data/app", `{"data":{"k":"v"}}`, root)

	lines := auditLines(t, path)
	// Find the request/response pair for the secret write.
	var sawReq, sawResp bool
	for _, l := range lines {
		if l["path"] == "secret/data/app" && l["type"] == "request" && l["operation"] == "update" {
			sawReq = true
		}
		if l["path"] == "secret/data/app" && l["type"] == "response" {
			sawResp = true
			if l["status_code"].(float64) != 200 {
				t.Fatalf("response status = %v, want 200", l["status_code"])
			}
		}
	}
	if !sawReq || !sawResp {
		t.Fatalf("missing audit entries (req=%v resp=%v) in %v", sawReq, sawResp, lines)
	}
}

func TestAuditNeverLogsRawToken(t *testing.T) {
	h, root, path := auditedHandler(t)
	doAuth(t, h, "GET", "/v1/secret/data/app", "", root)

	raw, _ := os.ReadFile(path) //nolint:gosec // G304: test path from t.TempDir()
	if strings.Contains(string(raw), root) {
		t.Fatal("root token leaked into audit log")
	}
	// But a token_hmac should be present for the authenticated request.
	var sawHMAC bool
	for _, l := range auditLines(t, path) {
		if l["token_hmac"] != nil && l["token_hmac"] != "" {
			sawHMAC = true
		}
	}
	if !sawHMAC {
		t.Fatal("expected a token_hmac for the authenticated request")
	}
}

// brokenDevice makes the broker fail, to test fail-closed request handling.
type brokenDevice struct{}

func (brokenDevice) Log(context.Context, *audit.Entry) error { return errors.New("boom") }
func (brokenDevice) Close() error                            { return nil }

func TestAuditFailClosedRefusesRequest(t *testing.T) {
	c := core.New(storage.NewMemoryBackend())
	h := NewHandler(c, WithAudit(audit.NewBroker(brokenDevice{})))

	// Even the unauthenticated seal-status endpoint must be refused if it can't
	// be audited.
	rec := do(t, h, "GET", "/v1/sys/seal-status", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure status = %d, want 500 (fail closed)", rec.Code)
	}
}

func TestNoAuditByDefault(t *testing.T) {
	// A handler without WithAudit must still serve normally.
	c := core.New(storage.NewMemoryBackend())
	h := NewHandler(c)
	if rec := do(t, h, "GET", "/v1/sys/seal-status", ""); rec.Code != http.StatusOK {
		t.Fatalf("no-audit handler status = %d, want 200", rec.Code)
	}
}
