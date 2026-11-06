package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// Every auth method follows Vault for role writes: a write to an existing role
// changes only the fields it sends, token_policies is accepted (and wins over
// policies), and list fields take comma strings.
func TestAuthRolePartialUpdates(t *testing.T) {
	h, root := unsealedHandler(t)
	_, _, caPEM := testCA(t)
	cert, _ := json.Marshal(caPEM)

	cases := []struct {
		name, path, create, update string
		want                       map[string]any // fields to check after the update
	}{
		{
			name:   "kubernetes",
			path:   "/v1/auth/kubernetes/role/app",
			create: `{"bound_service_account_names":["sa"],"bound_service_account_namespaces":"ns1,ns2","policies":["read"],"ttl":"1h"}`,
			update: `{"token_policies":"read,write"}`,
			want: map[string]any{
				"bound_service_account_names":      []any{"sa"},
				"bound_service_account_namespaces": []any{"ns1", "ns2"},
				"policies":                         []any{"read", "write"},
				"token_policies":                   []any{"read", "write"},
				"token_ttl":                        "1h0m0s",
			},
		},
		{
			name:   "approle",
			path:   "/v1/auth/approle/role/app",
			create: `{"policies":["read"],"token_ttl":"1h","secret_id_ttl":"10m"}`,
			update: `{"token_max_ttl":"2h"}`,
			want: map[string]any{
				"policies": []any{"read"}, "token_ttl": "1h0m0s", "token_max_ttl": "2h0m0s", "secret_id_ttl": "10m0s",
			},
		},
		{
			name:   "cert",
			path:   "/v1/auth/cert/certs/web",
			create: `{"certificate":` + string(cert) + `,"policies":["read"],"allowed_common_names":["alice"],"token_ttl":"1h"}`,
			update: `{"allowed_common_names":"alice,bob"}`,
			want: map[string]any{
				"policies": []any{"read"}, "allowed_common_names": []any{"alice", "bob"}, "certificate": caPEM,
			},
		},
		{
			name:   "userpass",
			path:   "/v1/auth/userpass/users/alice",
			create: `{"password":"pw-1","policies":["read"],"token_ttl":"30m"}`,
			update: `{"token_policies":["read","write"]}`,
			want: map[string]any{
				"policies": []any{"read", "write"}, "token_ttl": "30m0s",
			},
		},
	}
	for _, c := range cases {
		if rec := doAuth(t, h, "POST", c.path, c.create, root); rec.Code != http.StatusNoContent {
			t.Fatalf("%s create = %d %s", c.name, rec.Code, rec.Body.String())
		}
		if rec := doAuth(t, h, "POST", c.path, c.update, root); rec.Code != http.StatusNoContent {
			t.Fatalf("%s update = %d %s", c.name, rec.Code, rec.Body.String())
		}
		data := decode[map[string]any](t, doAuth(t, h, "GET", c.path, "", root))["data"].(map[string]any)
		for k, v := range c.want {
			if !reflect.DeepEqual(data[k], v) {
				t.Errorf("%s: %s = %#v, want %#v", c.name, k, data[k], v)
			}
		}
		// The TTL limit applies to the merged role, not just to the fields sent.
		if rec := doAuth(t, h, "POST", c.path, `{"token_max_ttl":"1m"}`, root); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: max below the stored ttl = %d, want 400", c.name, rec.Code)
		}
	}
}

func TestUserpassUpdateKeepsPassword(t *testing.T) {
	h, root := unsealedHandler(t)
	doAuth(t, h, "POST", "/v1/auth/userpass/users/alice", `{"password":"pw-1","policies":["read"]}`, root)
	if rec := doAuth(t, h, "POST", "/v1/auth/userpass/users/alice", `{"policies":["read","write"]}`, root); rec.Code != http.StatusNoContent {
		t.Fatalf("update = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "POST", "/v1/auth/userpass/login/alice", `{"password":"pw-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("login with the kept password = %d %s", rec.Code, rec.Body.String())
	}
	// A new password replaces it.
	doAuth(t, h, "POST", "/v1/auth/userpass/users/alice", `{"password":"pw-2"}`, root)
	if rec := do(t, h, "POST", "/v1/auth/userpass/login/alice", `{"password":"pw-1"}`); rec.Code == http.StatusOK {
		t.Fatal("old password still works after a change")
	}
	if rec := do(t, h, "POST", "/v1/auth/userpass/login/alice", `{"password":"pw-2"}`); rec.Code != http.StatusOK {
		t.Fatalf("login with the new password = %d", rec.Code)
	}
	// A new user still needs a password and policies.
	if rec := doAuth(t, h, "POST", "/v1/auth/userpass/users/bob", `{"policies":["read"]}`, root); rec.Code != http.StatusBadRequest {
		t.Fatalf("new user without password = %d, want 400", rec.Code)
	}
	if rec := doAuth(t, h, "POST", "/v1/auth/userpass/users/bob", `{"password":"x"}`, root); rec.Code != http.StatusBadRequest {
		t.Fatalf("new user without policies = %d, want 400", rec.Code)
	}
}

// The root guard holds through token_policies and partial updates too.
func TestPartialUpdateCannotAddRoot(t *testing.T) {
	h, root := unsealedHandler(t)
	doAuth(t, h, "POST", "/v1/auth/approle/role/app", `{"policies":["read"]}`, root)
	for _, body := range []string{`{"token_policies":["root"]}`, `{"policies":"read,root"}`} {
		if rec := doAuth(t, h, "POST", "/v1/auth/approle/role/app", body, root); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", body, rec.Code)
		}
	}
	data := decode[map[string]any](t, doAuth(t, h, "GET", "/v1/auth/approle/role/app", "", root))["data"].(map[string]any)
	if !reflect.DeepEqual(data["policies"], []any{"read"}) {
		t.Fatalf("policies = %v after refused updates, want [read]", data["policies"])
	}
}
