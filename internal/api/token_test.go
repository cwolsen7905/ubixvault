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

// createPlainToken mints a 1h token whose only policy grants nothing, so any
// access it has comes from built-in rules rather than an ACL grant.
func createPlainToken(t *testing.T, h http.Handler, root string) string {
	t.Helper()
	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["nothing"],"ttl":"1h"}`, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d, body=%s", rec.Code, rec.Body.String())
	}
	return decode[map[string]any](t, rec)["auth"].(map[string]any)["client_token"].(string)
}

func TestLookupSelfWithoutGrant(t *testing.T) {
	h, root := unsealedHandler(t)
	tok := createPlainToken(t, h, root)

	rec := doAuth(t, h, "GET", "/v1/auth/token/lookup-self", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup-self = %d, body=%s", rec.Code, rec.Body.String())
	}
	d := decode[map[string]any](t, rec)["data"].(map[string]any)
	if d["id"] != tok {
		t.Errorf("id = %v, want the calling token", d["id"])
	}
	if p := d["policies"].([]any); len(p) != 1 || p[0] != "nothing" {
		t.Errorf("policies = %v, want [nothing]", p)
	}
	if ttl := d["ttl"].(float64); ttl < 3500 || ttl > 3600 {
		t.Errorf("ttl = %v, want ~3600", ttl)
	}
	if d["expire_time"] == nil || d["renewable"] != true || d["type"] != "service" {
		t.Errorf("expire_time=%v renewable=%v type=%v", d["expire_time"], d["renewable"], d["type"])
	}
	if _, ok := d["identity_policies"].([]any); !ok {
		t.Errorf("identity_policies = %v, want a (possibly empty) list", d["identity_policies"])
	}
}

func TestLookupSelfRootToken(t *testing.T) {
	h, root := unsealedHandler(t)
	rec := doAuth(t, h, "GET", "/v1/auth/token/lookup-self", "", root)
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup-self = %d, body=%s", rec.Code, rec.Body.String())
	}
	d := decode[map[string]any](t, rec)["data"].(map[string]any)
	if d["expire_time"] != nil || d["ttl"].(float64) != 0 || d["renewable"] != false {
		t.Errorf("root: expire_time=%v ttl=%v renewable=%v, want null/0/false", d["expire_time"], d["ttl"], d["renewable"])
	}
}

func TestLookupSelfRequiresToken(t *testing.T) {
	h, _ := unsealedHandler(t)
	if rec := doAuth(t, h, "GET", "/v1/auth/token/lookup-self", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}
}

func TestRevokeSelfWithoutGrant(t *testing.T) {
	h, root := unsealedHandler(t)
	tok := createPlainToken(t, h, root)

	if rec := doAuth(t, h, "POST", "/v1/auth/token/revoke-self", "", tok); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke-self = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec := doAuth(t, h, "GET", "/v1/auth/token/lookup-self", "", tok); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked token lookup-self = %d, want 403", rec.Code)
	}
}

// Renewal has no maximum TTL, so it must stay behind an explicit grant: a token
// that could renew itself by default could make itself effectively permanent.
func TestRenewSelfStillNeedsGrant(t *testing.T) {
	h, root := unsealedHandler(t)
	tok := createPlainToken(t, h, root)
	if rec := doAuth(t, h, "POST", "/v1/auth/token/renew-self", `{"increment":"87600h"}`, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("renew-self without a grant = %d, want 403", rec.Code)
	}
}
