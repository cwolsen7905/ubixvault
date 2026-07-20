package api

import (
	"net/http"
	"testing"
)

func TestHealthUninitialized(t *testing.T) {
	h := newTestHandler()
	rec := do(t, h, "GET", "/v1/sys/health", "")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("uninitialized health = %d, want 501", rec.Code)
	}
	body := decode[healthResponse](t, rec)
	if body.Initialized || !body.Sealed {
		t.Fatalf("health body = %+v", body)
	}
}

func TestHealthSealed(t *testing.T) {
	h := newTestHandler()
	do(t, h, "POST", "/v1/sys/init", `{"secret_shares":2,"secret_threshold":2}`)
	// Initialized but sealed.
	rec := do(t, h, "GET", "/v1/sys/health", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("sealed health = %d, want 503", rec.Code)
	}
	if body := decode[healthResponse](t, rec); !body.Initialized || !body.Sealed {
		t.Fatalf("health body = %+v", body)
	}
}

func TestHealthReady(t *testing.T) {
	h, _ := unsealedHandler(t)
	rec := do(t, h, "GET", "/v1/sys/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ready health = %d, want 200", rec.Code)
	}
	body := decode[healthResponse](t, rec)
	if !body.Initialized || body.Sealed {
		t.Fatalf("health body = %+v", body)
	}
	if body.ServerTimeUTC == 0 {
		t.Fatal("server_time_utc not set")
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	h, _ := unsealedHandler(t)
	// No X-Vault-Token — health must still respond 200.
	if rec := do(t, h, "GET", "/v1/sys/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("health without token = %d, want 200", rec.Code)
	}
}
