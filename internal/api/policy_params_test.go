package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The Neptune superuser policy from the feature request: manage JWT login
// roles, but only hand out the listed read policies.
const superuserPolicy = `{"path":{"auth/jwt/role/*":{
  "capabilities":["create","read","update","list"],
  "allowed_parameters":{
    "policies":["neptune-prod-read","vs3-com-ws-flirt4free-prod-read"],
    "token_policies":["neptune-prod-read","vs3-com-ws-flirt4free-prod-read"],
    "*":[]
  }}}}`

func superuser(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "neptune-vault-prod-superusers", superuserPolicy)
	su := tokenWith(t, h, root, `{"policies":["neptune-vault-prod-superusers"],"ttl":"1h"}`)
	return h, root, su
}

// Acceptance tests 1–4.
func TestAllowedParametersLimitRolePolicies(t *testing.T) {
	h, _, su := superuser(t)
	cases := []struct {
		body string
		want int
	}{
		{`{"policies":["neptune-prod-read"]}`, http.StatusNoContent},
		{`{"token_policies":["neptune-prod-read","vs3-com-ws-flirt4free-prod-read"]}`, http.StatusNoContent},
		{`{"policies":"neptune-prod-read"}`, http.StatusNoContent},
		{`{"policies":["neptune-prod-read"],"bound_audiences":["anything"],"token_ttl":"1h"}`, http.StatusNoContent},

		{`{"policies":["root"]}`, http.StatusForbidden},
		{`{"policies":["neptune-vault-prod-superusers"]}`, http.StatusForbidden},
		{`{"policies":["neptune-prod-read","root"]}`, http.StatusForbidden},
		{`{"token_policies":["root"]}`, http.StatusForbidden},
		{`{"token_policies":["neptune-vault-prod-superusers"]}`, http.StatusForbidden},
		{`{"token_policies":["neptune-prod-read","root"]}`, http.StatusForbidden},
		{`{"policies":"neptune-prod-read,root"}`, http.StatusForbidden},
		{`{"token_policies":"neptune-prod-read,root"}`, http.StatusForbidden},

		// Names match case-insensitively, so case can't dodge the limit.
		{`{"POLICIES":["root"]}`, http.StatusForbidden},
		{`{"policies":["neptune-prod-read"],"Token_Policies":["root"]}`, http.StatusForbidden},
		// Unicode folding the JSON decoder applies (long s) can't dodge it.
		{`{"policie\u017f":["root"]}`, http.StatusForbidden},
		{"{\"token_policie\u017f\":[\"root\"]}", http.StatusForbidden},
		// A body the check cannot read is refused, not waved through.
		{`["policies","root"]`, http.StatusForbidden},
		{`{"policies":["root"]`, http.StatusForbidden},
	}
	for _, c := range cases {
		rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/app", c.body, su)
		if rec.Code != c.want {
			t.Errorf("%s = %d %s, want %d", c.body, rec.Code, rec.Body.String(), c.want)
		}
		if c.want == http.StatusForbidden && !strings.Contains(rec.Body.String(), "permission denied") {
			t.Errorf("%s: body %s, want permission denied", c.body, rec.Body.String())
		}
	}
}

// Acceptance test 5: an update that does not send policies keeps them.
func TestRoleUpdateWithoutPoliciesKeepsThem(t *testing.T) {
	h, _, su := superuser(t)
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/app", `{"policies":["neptune-prod-read"],"token_ttl":"1h"}`, su); rec.Code != http.StatusNoContent {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/app", `{"bound_claims":{"sub":"system:serviceaccount:neptune:app"}}`, su); rec.Code != http.StatusNoContent {
		t.Fatalf("update = %d %s", rec.Code, rec.Body.String())
	}
	data := decode[map[string]any](t, doAuth(t, h, "GET", "/v1/auth/jwt/role/app", "", su))["data"].(map[string]any)
	if p := data["policies"].([]any); len(p) != 1 || p[0] != "neptune-prod-read" {
		t.Fatalf("policies = %v, want [neptune-prod-read]", p)
	}
	if c := data["bound_claims"].(map[string]any); c["sub"] != "system:serviceaccount:neptune:app" {
		t.Fatalf("bound_claims = %v", c)
	}
	if data["token_ttl"] != "1h0m0s" {
		t.Fatalf("token_ttl = %v, want kept at 1h", data["token_ttl"])
	}
	// A new role still needs policies.
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/new", `{"bound_claims":{"sub":"x"}}`, su); rec.Code != http.StatusBadRequest {
		t.Fatalf("create without policies = %d, want 400", rec.Code)
	}
}

// Acceptance test 6: denied_parameters wins over allowed_parameters.
func TestDeniedParametersWin(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "p", `{"path":{"auth/jwt/role/*":{"capabilities":["create","update"],
	  "allowed_parameters":{"policies":["neptune-prod-read","legacy"],"*":[]},
	  "denied_parameters":{"policies":["legacy"],"token_ttl":[]}}}}`)
	tok := tokenWith(t, h, root, `{"policies":["p"],"ttl":"1h"}`)
	for body, want := range map[string]int{
		`{"policies":["neptune-prod-read"]}`:                  http.StatusNoContent,
		`{"policies":["legacy"]}`:                             http.StatusForbidden,
		`{"policies":["neptune-prod-read","legacy"]}`:         http.StatusForbidden,
		`{"policies":["neptune-prod-read"],"token_ttl":"1h"}`: http.StatusForbidden,
	} {
		if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/app", body, tok); rec.Code != want {
			t.Errorf("%s = %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
}

// A broader unrestricted grant in another policy does not lift the limits set
// on the more specific path.
func TestBroaderGrantDoesNotLiftLimits(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "neptune-vault-prod-superusers", superuserPolicy)
	setPolicy(t, h, root, "broad", `{"path":{"auth/*":{"capabilities":["create","update"]}}}`)
	tok := tokenWith(t, h, root, `{"policies":["neptune-vault-prod-superusers","broad"],"ttl":"1h"}`)
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/app", `{"policies":["neptune-vault-prod-superusers"]}`, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("escalation through broad grant = %d %s, want 403", rec.Code, rec.Body.String())
	}
	// The broad grant still works on paths the limit does not cover.
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/config", `{"validation_pubkeys":["x"]}`, tok); rec.Code == http.StatusForbidden {
		t.Fatalf("broad grant elsewhere = 403, want allowed")
	}
}

// Acceptance test 8: the policy reads back with the fields as written, in both
// formats, and the HCL form enforces the same limits.
func TestParameterPolicyRoundTrips(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "su", superuserPolicy)
	rec := doAuth(t, h, "GET", "/v1/sys/policies/acl/su", "", root)
	text := decode[map[string]any](t, rec)["data"].(map[string]any)["policy"].(string)
	for _, want := range []string{`"allowed_parameters"`, `"token_policies":["neptune-prod-read","vs3-com-ws-flirt4free-prod-read"]`, `"*":[]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("read back %s, missing %s", text, want)
		}
	}
	// Writing the text back stores the same policy.
	setPolicy(t, h, root, "su2", `{"policy":`+quoteJSON(text)+`}`)
	again := decode[map[string]any](t, doAuth(t, h, "GET", "/v1/sys/policies/acl/su2", "", root))["data"].(map[string]any)["policy"].(string)
	if again != text {
		t.Fatalf("round trip changed the policy:\n%s\n%s", text, again)
	}

	hcl := `path "auth/jwt/role/*" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "policies" = ["neptune-prod-read"]
    "*"        = []
  }
}`
	setPolicy(t, h, root, "hcl", `{"policy":`+quoteJSON(hcl)+`}`)
	tok := tokenWith(t, h, root, `{"policies":["hcl"],"ttl":"1h"}`)
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/a", `{"policies":["root"]}`, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("HCL policy: root = %d, want 403", rec.Code)
	}
	if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/a", `{"policies":["neptune-prod-read"]}`, tok); rec.Code != http.StatusNoContent {
		t.Fatalf("HCL policy: allowed = %d %s", rec.Code, rec.Body.String())
	}
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// A glob value must not pass a comma string the handler splits into several
// policies (Kelpie review of !62).
func TestGlobDoesNotPassCommaString(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "globby", `{"path":{"auth/jwt/role/*":{"capabilities":["create","update"],
	  "allowed_parameters":{"policies":["neptune-*"],"*":[]}}}}`)
	setPolicy(t, h, root, "neptune-x", `{"path":{"secret/*":{"capabilities":["read"]}}}`)
	tok := tokenWith(t, h, root, `{"policies":["globby"],"ttl":"1h"}`)
	for body, want := range map[string]int{
		`{"policies":"neptune-x,admin"}`:   http.StatusForbidden,
		`{"policies":["neptune-x,admin"]}`: http.StatusForbidden,
		`{"policies":"neptune-x"}`:         http.StatusNoContent,
	} {
		if rec := doAuth(t, h, "POST", "/v1/auth/jwt/role/app", body, tok); rec.Code != want {
			t.Errorf("%s = %d %s, want %d", body, rec.Code, rec.Body.String(), want)
		}
	}
}
