package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestUIRootRedirect(t *testing.T) {
	h := newTestHandler()
	rec := do(t, h, "GET", "/", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("GET / = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/" {
		t.Fatalf("redirect Location = %q, want /ui/", loc)
	}
}

func TestUIServesConsole(t *testing.T) {
	h := newTestHandler()

	rec := do(t, h, "GET", "/ui/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui/ = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("missing/loose CSP: %q", csp)
	}
	if body := rec.Body.String(); !strings.Contains(body, "uBix") || !strings.Contains(body, "console.js") {
		t.Fatalf("console HTML unexpected: %q", body)
	}

	// Static assets are served too.
	for _, asset := range []string{"/ui/console.js", "/ui/console.css"} {
		if r := do(t, h, "GET", asset, ""); r.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", asset, r.Code)
		}
	}
}

func TestUIDoesNotShadowAPI(t *testing.T) {
	h := newTestHandler()
	// Unknown paths still 404; the API is unaffected.
	if r := do(t, h, "GET", "/nope", ""); r.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", r.Code)
	}
	if r := do(t, h, "GET", "/v1/sys/health", ""); r.Code == http.StatusNotFound {
		t.Errorf("health route should not be shadowed by the UI")
	}
}
