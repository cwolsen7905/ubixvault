package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestPortalRootServesPlaceholder(t *testing.T) {
	h := newTestHandler()
	rec := do(t, h, "GET", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "Admin Portal") || !strings.Contains(body, "Coming soon") {
		t.Fatalf("body missing placeholder text: %q", body)
	}
}

func TestPortalDoesNotShadowAPIOr404(t *testing.T) {
	h := newTestHandler()
	// An unknown path is still a 404 — the root placeholder is anchored to "/".
	if rec := do(t, h, "GET", "/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404", rec.Code)
	}
	// A real API route is unaffected by the root registration (not a 404).
	if rec := do(t, h, "GET", "/v1/sys/health", ""); rec.Code == http.StatusNotFound {
		t.Fatalf("GET /v1/sys/health = 404, root route should not shadow it")
	}
}
