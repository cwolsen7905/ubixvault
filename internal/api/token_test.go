package api

import (
	"net/http"
	"testing"
)

func TestTokenCreateWithTTL(t *testing.T) {
	h, root := unsealedHandler(t)
	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["p"],"ttl":"1h"}`, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d, body=%s", rec.Code, rec.Body.String())
	}
	auth := decode[map[string]any](t, rec)["auth"].(map[string]any)
	if ld := auth["lease_duration"].(float64); ld < 3500 || ld > 3600 {
		t.Fatalf("lease_duration = %v, want ~3600", ld)
	}
}

func TestTokenCreateDefaultTTL(t *testing.T) {
	h, root := unsealedHandler(t)
	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["p"]}`, root)
	auth := decode[map[string]any](t, rec)["auth"].(map[string]any)
	if auth["lease_duration"].(float64) <= 0 {
		t.Fatalf("default lease_duration should be positive, got %v", auth["lease_duration"])
	}
}

// TestExpiredTokenRejected creates a token that expires essentially immediately
// (1ns) and confirms the middleware rejects it on the next request.
func TestExpiredTokenRejected(t *testing.T) {
	h, root := unsealedHandler(t)
	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["p"],"ttl":"1ns"}`, root)
	expired := decode[map[string]any](t, rec)["auth"].(map[string]any)["client_token"].(string)

	if rec := doAuth(t, h, "GET", "/v1/secret/data/anything", "", expired); rec.Code != http.StatusForbidden {
		t.Fatalf("expired token = %d, want 403", rec.Code)
	}
}

func TestRenewSelfExtendsLease(t *testing.T) {
	h, root := unsealedHandler(t)
	// A policy that lets a token renew itself.
	doAuth(t, h, "PUT", "/v1/sys/policies/acl/renewer",
		`{"path":{"auth/token/renew-self":{"capabilities":["update"]}}}`, root)
	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["renewer"],"ttl":"1h"}`, root)
	tok := decode[map[string]any](t, rec)["auth"].(map[string]any)["client_token"].(string)

	rec = doAuth(t, h, "POST", "/v1/auth/token/renew-self", `{"increment":"2h"}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew-self = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ld := decode[map[string]any](t, rec)["auth"].(map[string]any)["lease_duration"].(float64); ld < 7100 || ld > 7200 {
		t.Fatalf("renewed lease_duration = %v, want ~7200", ld)
	}
}
