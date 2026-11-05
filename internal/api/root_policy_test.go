package api

import (
	"net/http"
	"strings"
	"testing"
)

// Root tokens come only from init and generate-root (a quorum of unseal
// shares), or from another root token. No auth method role may carry the root
// policy, whoever writes it: a login through such a role would be root.
func TestAuthMethodsRefuseRootPolicy(t *testing.T) {
	h, root := unsealedHandler(t)
	writes := map[string]string{
		"/v1/auth/jwt/role/r":        `{"policies":["neptune-prod-read","root"]}`,
		"/v1/auth/kubernetes/role/r": `{"bound_service_account_names":["sa"],"bound_service_account_namespaces":["ns"],"policies":["root"]}`,
		"/v1/auth/approle/role/r":    `{"policies":["root"]}`,
		"/v1/auth/userpass/users/u":  `{"password":"pw","policies":["Root"]}`,
		"/v1/auth/cert/certs/c":      `{"certificate":"unused","policies":["root"]}`,
	}
	for path, body := range writes {
		rec := doAuth(t, h, "POST", path, body, root)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "root policy") {
			t.Errorf("POST %s = %d %s, want 400 refusing the root policy", path, rec.Code, rec.Body.String())
		}
	}
}

func TestLDAPGroupRefusesRootPolicy(t *testing.T) {
	h, root := unsealedLDAPHandler(t, fakeLDAP{})
	rec := doAuth(t, h, "POST", "/v1/auth/ldap/groups/admins", `{"policies":["root"]}`, root)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ldap group with root = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

// A sudo grant on auth/token/create allows any policy except root.
func TestOnlyRootCanCreateRootTokens(t *testing.T) {
	h, root := unsealedHandler(t)
	setPolicy(t, h, root, "issuer", `{"path":{"auth/token/create":{"capabilities":["update","sudo"]}}}`)
	issuer := tokenWith(t, h, root, `{"policies":["issuer"],"ttl":"1h"}`)

	rec := doAuth(t, h, "POST", "/v1/auth/token/create", `{"policies":["root"]}`, issuer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sudo create root = %d %s, want 400", rec.Code, rec.Body.String())
	}
	// Root itself still can.
	tokenWith(t, h, root, `{"policies":["root"],"ttl":"1h"}`)
}

func TestPolicyNameRootIsReserved(t *testing.T) {
	h, root := unsealedHandler(t)
	for _, name := range []string{"root", "ROOT"} {
		rec := doAuth(t, h, "PUT", "/v1/sys/policies/acl/"+name, `{"path":{"*":{"capabilities":["read"]}}}`, root)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("write policy %q = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
}
