package api

import (
	"net/http"
	"testing"
)

// unsealedHandler returns a handler whose vault is initialized and unsealed.
func unsealedHandler(t *testing.T) http.Handler {
	t.Helper()
	h := newTestHandler()
	init := decode[initResponse](t, do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`))
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[0]+`"}`)
	do(t, h, "POST", "/v1/sys/unseal", `{"key":"`+init.Keys[1]+`"}`)
	return h
}

func TestSecretWriteReadRoundTrip(t *testing.T) {
	h := unsealedHandler(t)

	rec := do(t, h, "POST", "/v1/secret/data/app/db", `{"data":{"user":"admin","pass":"hunter2"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("write status = %d, body=%s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, "GET", "/v1/secret/data/app/db", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("read status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := decode[map[string]any](t, rec)
	data := body["data"].(map[string]any)
	secret := data["data"].(map[string]any)
	if secret["user"] != "admin" || secret["pass"] != "hunter2" {
		t.Fatalf("round-trip secret = %v", secret)
	}
}

func TestSecretVersioningOverHTTP(t *testing.T) {
	h := unsealedHandler(t)
	do(t, h, "POST", "/v1/secret/data/p", `{"data":{"v":"1"}}`)
	do(t, h, "POST", "/v1/secret/data/p", `{"data":{"v":"2"}}`)

	// Latest.
	body := decode[map[string]any](t, do(t, h, "GET", "/v1/secret/data/p", ""))
	if body["data"].(map[string]any)["data"].(map[string]any)["v"] != "2" {
		t.Fatalf("latest = %v", body)
	}
	// Specific old version.
	body = decode[map[string]any](t, do(t, h, "GET", "/v1/secret/data/p?version=1", ""))
	if body["data"].(map[string]any)["data"].(map[string]any)["v"] != "1" {
		t.Fatalf("v1 = %v", body)
	}
}

func TestSecretOpsFailWhenSealed(t *testing.T) {
	h := newTestHandler() // initialized? no — not even initialized, definitely sealed
	do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`)
	// Initialized but sealed.
	rec := do(t, h, "POST", "/v1/secret/data/p", `{"data":{"a":"b"}}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("write while sealed = %d, want 503", rec.Code)
	}
	rec = do(t, h, "GET", "/v1/secret/data/p", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("read while sealed = %d, want 503", rec.Code)
	}
}

func TestSecretReadMissing(t *testing.T) {
	h := unsealedHandler(t)
	rec := do(t, h, "GET", "/v1/secret/data/nope", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("read missing = %d, want 404", rec.Code)
	}
}

func TestSecretSoftDeleteUndelete(t *testing.T) {
	h := unsealedHandler(t)
	do(t, h, "POST", "/v1/secret/data/p", `{"data":{"a":"b"}}`)

	if rec := do(t, h, "DELETE", "/v1/secret/data/p", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/secret/data/p", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("read after delete = %d, want 404", rec.Code)
	}
	if rec := do(t, h, "POST", "/v1/secret/undelete/p", `{"versions":[1]}`); rec.Code != http.StatusNoContent {
		t.Fatalf("undelete = %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/secret/data/p", ""); rec.Code != http.StatusOK {
		t.Fatalf("read after undelete = %d, want 200", rec.Code)
	}
}

func TestSecretDestroy(t *testing.T) {
	h := unsealedHandler(t)
	do(t, h, "POST", "/v1/secret/data/p", `{"data":{"a":"b"}}`)
	if rec := do(t, h, "POST", "/v1/secret/destroy/p", `{"versions":[1]}`); rec.Code != http.StatusNoContent {
		t.Fatalf("destroy = %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/secret/data/p?version=1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("read destroyed = %d, want 404", rec.Code)
	}
}

func TestSecretMetadataAndList(t *testing.T) {
	h := unsealedHandler(t)
	do(t, h, "POST", "/v1/secret/data/team/a", `{"data":{"x":"1"}}`)
	do(t, h, "POST", "/v1/secret/data/team/a", `{"data":{"x":"2"}}`)
	do(t, h, "POST", "/v1/secret/data/team/b", `{"data":{"x":"1"}}`)

	// Metadata reports version history.
	body := decode[map[string]any](t, do(t, h, "GET", "/v1/secret/metadata/team/a", ""))
	if body["data"].(map[string]any)["current_version"].(float64) != 2 {
		t.Fatalf("metadata current_version = %v", body)
	}

	// List children under team/.
	rec := do(t, h, "LIST", "/v1/secret/metadata/team", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	keys := decode[map[string]any](t, rec)["data"].(map[string]any)["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("list keys = %v, want 2", keys)
	}
}

func TestSecretDeleteMetadataRemovesAll(t *testing.T) {
	h := unsealedHandler(t)
	do(t, h, "POST", "/v1/secret/data/p", `{"data":{"a":"b"}}`)
	if rec := do(t, h, "DELETE", "/v1/secret/metadata/p", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete metadata = %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/v1/secret/metadata/p", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("metadata after delete = %d, want 404", rec.Code)
	}
}

func TestSecretWriteAcceptsOptions(t *testing.T) {
	h := unsealedHandler(t)
	// Vault clients send an "options" object; it must be accepted (ignored).
	rec := do(t, h, "POST", "/v1/secret/data/p", `{"data":{"a":"b"},"options":{"cas":0}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("write with options = %d, body=%s", rec.Code, rec.Body.String())
	}
}
