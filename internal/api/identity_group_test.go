package api

import (
	"net/http"
	"testing"
)

// TestGroupPolicyGrantsAcrossToken is the Phase-2 headline over HTTP: adding an
// entity to a group with a policy grants a pre-existing token new access,
// resolved per-request.
func TestGroupPolicyGrantsAcrossToken(t *testing.T) {
	h, root := unsealedHandler(t)

	doAuth(t, h, "PUT", "/v1/sys/policies/acl/kv-reader",
		`{"path":{"secret/data/team":{"capabilities":["read","create","update"]}}}`, root)

	auth := makeUserAndLogin(t, h, root, "alice", "pw", `["base"]`)
	tok := auth["client_token"].(string)
	entity := auth["entity_id"].(string)

	// No access yet.
	if rec := doAuth(t, h, "POST", "/v1/secret/data/team", `{"data":{"k":"v"}}`, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("pre-group write = %d, want 403", rec.Code)
	}

	// Create a group carrying the policy, with alice's entity as a member.
	rec := doAuth(t, h, "POST", "/v1/identity/group",
		`{"name":"platform","policies":["kv-reader"],"member_entity_ids":["`+entity+`"]}`, root)
	if rec.Code != http.StatusOK {
		t.Fatalf("create group = %d, body=%s", rec.Code, rec.Body.String())
	}
	gid := decode[map[string]any](t, rec)["data"].(map[string]any)["id"].(string)

	// The same token now has access via the group policy.
	if rec := doAuth(t, h, "POST", "/v1/secret/data/team", `{"data":{"k":"v"}}`, tok); rec.Code != http.StatusOK {
		t.Fatalf("post-group write = %d, body=%s, want 200", rec.Code, rec.Body.String())
	}

	// Reading the group back and listing it works.
	if rec := doAuth(t, h, "GET", "/v1/identity/group/id/"+gid, "", root); rec.Code != http.StatusOK {
		t.Fatalf("read group = %d", rec.Code)
	}
	if rec := doAuth(t, h, "GET", "/v1/identity/group/name/platform", "", root); rec.Code != http.StatusOK {
		t.Fatalf("read group by name = %d", rec.Code)
	}

	// Removing the member (update by id, empty membership) revokes the access.
	if rec := doAuth(t, h, "POST", "/v1/identity/group",
		`{"id":"`+gid+`","policies":["kv-reader"],"member_entity_ids":[]}`, root); rec.Code != http.StatusOK {
		t.Fatalf("update group = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec := doAuth(t, h, "GET", "/v1/secret/data/team", "", tok); rec.Code != http.StatusForbidden {
		t.Fatalf("after removal read = %d, want 403", rec.Code)
	}
}

func TestGroupNotFound(t *testing.T) {
	h, root := unsealedHandler(t)
	if rec := doAuth(t, h, "GET", "/v1/identity/group/id/nope", "", root); rec.Code != http.StatusNotFound {
		t.Fatalf("missing group = %d, want 404", rec.Code)
	}
}
