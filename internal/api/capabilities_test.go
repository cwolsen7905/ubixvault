package api

import (
	"net/http"
	"reflect"
	"testing"
)

func capsOf(t *testing.T, h http.Handler, path, body, tok string) map[string]any {
	t.Helper()
	rec := doAuth(t, h, "POST", path, body, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s %s = %d %s", path, body, rec.Code, rec.Body.String())
	}
	return decode[map[string]any](t, rec)
}

func TestCapabilitiesSelf(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "app", `{"path":{
	  "secret/data/app/*":{"capabilities":["read","list"]},
	  "secret/data/app/admin":{"capabilities":["deny"]},
	  "secret/data/shared":{"capabilities":["update"]}}}`)
	setPolicy(t, h, root, "more", `{"path":{"secret/data/shared":{"capabilities":["create","read"]}}}`)
	tok := tokenWith(t, h, root, `{"policies":["app","more"],"ttl":"1h"}`)

	// A token with no grant on sys/capabilities-self may still call it.
	resp := capsOf(t, h, "/v1/sys/capabilities-self",
		`{"paths":["secret/data/app/x","secret/data/app/admin","secret/data/shared","/secret/data/other","cubbyhole/notes","auth/token/lookup-self"]}`, tok)
	data := resp["data"].(map[string]any)
	want := map[string][]any{
		"secret/data/app/x":      {"list", "read"},
		"secret/data/app/admin":  {"deny"},                     // deny wins
		"secret/data/shared":     {"create", "read", "update"}, // merged across policies
		"/secret/data/other":     {"deny"},                     // nothing granted
		"cubbyhole/notes":        {"create", "delete", "list", "read", "update"},
		"auth/token/lookup-self": {"read"},
	}
	for p, w := range want {
		if !reflect.DeepEqual(data[p], w) {
			t.Errorf("data[%q] = %v, want %v", p, data[p], w)
		}
		if !reflect.DeepEqual(resp[p], w) {
			t.Errorf("top-level %q = %v, want %v", p, resp[p], w)
		}
	}
	if _, ok := data["capabilities"]; ok {
		t.Error(`"capabilities" should appear only for a single path`)
	}

	// One path: also under "capabilities" (Vault's older clients read that),
	// and the older "path" field works.
	one := capsOf(t, h, "/v1/sys/capabilities-self", `{"path":"secret/data/app/x"}`, tok)
	if !reflect.DeepEqual(one["data"].(map[string]any)["capabilities"], []any{"list", "read"}) {
		t.Errorf("single path = %v", one)
	}
	// Root reports root.
	r := capsOf(t, h, "/v1/sys/capabilities-self", `{"paths":["anything"]}`, root)
	if !reflect.DeepEqual(r["data"].(map[string]any)["anything"], []any{"root"}) {
		t.Errorf("root = %v", r)
	}
	// Errors.
	for _, body := range []string{`{}`, `{"paths":[]}`, `{"paths":["a"],"token":"x"}`} {
		if rec := doAuth(t, h, "POST", "/v1/sys/capabilities-self", body, tok); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, rec.Code)
		}
	}
	if rec := do(t, h, "POST", "/v1/sys/capabilities-self", `{"paths":["a"]}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", rec.Code)
	}
}

// Templated policies report their expanded paths.
func TestCapabilitiesSelfTemplated(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "own", `{"path":{"secret/data/users/{{identity.entity.name}}/*":{"capabilities":["create","read"]}}}`)
	doAuth(t, h, "POST", "/v1/auth/userpass/users/alice", `{"password":"pw","policies":["own"]}`, root)
	rec := do(t, h, "POST", "/v1/auth/userpass/login/alice", `{"password":"pw"}`)
	tok := decode[map[string]any](t, rec)["auth"].(map[string]any)["client_token"].(string)
	resp := capsOf(t, h, "/v1/sys/capabilities-self", `{"paths":["secret/data/users/userpass/alice/db","secret/data/users/bob/db"]}`, tok)
	data := resp["data"].(map[string]any)
	if !reflect.DeepEqual(data["secret/data/users/userpass/alice/db"], []any{"create", "read"}) {
		t.Errorf("own path = %v", data)
	}
	if !reflect.DeepEqual(data["secret/data/users/bob/db"], []any{"deny"}) {
		t.Errorf("other user's path = %v", data)
	}
}

// sys/capabilities asks about another token and needs a grant, like Vault.
func TestCapabilitiesOtherToken(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "app", `{"path":{"secret/data/app":{"capabilities":["read"]}}}`)
	setPolicy(t, h, root, "auditor", `{"path":{"sys/capabilities":{"capabilities":["update"]}}}`)
	app := tokenWith(t, h, root, `{"policies":["app"],"ttl":"1h"}`)
	auditor := tokenWith(t, h, root, `{"policies":["auditor"],"ttl":"1h"}`)

	if rec := doAuth(t, h, "POST", "/v1/sys/capabilities", `{"token":"`+auditor+`","paths":["x"]}`, app); rec.Code != http.StatusForbidden {
		t.Fatalf("without a grant = %d, want 403", rec.Code)
	}
	resp := capsOf(t, h, "/v1/sys/capabilities", `{"token":"`+app+`","paths":["secret/data/app"]}`, auditor)
	if !reflect.DeepEqual(resp["data"].(map[string]any)["secret/data/app"], []any{"read"}) {
		t.Errorf("app caps = %v", resp)
	}
	for _, body := range []string{`{"paths":["x"]}`, `{"token":"uv.nope","paths":["x"]}`} {
		if rec := doAuth(t, h, "POST", "/v1/sys/capabilities", body, auditor); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, rec.Code)
		}
	}
}
