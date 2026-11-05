package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := ParseDocument("p", []byte(doc))
	if err != nil {
		t.Fatalf("parse %s: %v", doc, err)
	}
	return p
}

func body(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParametersAllows(t *testing.T) {
	cases := []struct {
		name, allowed, denied, data string
		want                        bool
	}{
		{"no data", `{"a":["x"]}`, ``, `{}`, true},
		{"listed value", `{"a":["x","y"]}`, ``, `{"a":"x"}`, true},
		{"unlisted value", `{"a":["x"]}`, ``, `{"a":"z"}`, false},
		{"empty list is any value", `{"a":[]}`, ``, `{"a":"anything"}`, true},
		{"unnamed parameter refused", `{"a":[]}`, ``, `{"b":"x"}`, false},
		{"star allows unnamed", `{"a":["x"],"*":[]}`, ``, `{"b":"x"}`, true},
		{"star keeps named limited", `{"a":["x"],"*":[]}`, ``, `{"a":"z"}`, false},
		{"only star", `{"*":[]}`, ``, `{"q":1}`, true},
		{"list: all listed", `{"a":["x","y"]}`, ``, `{"a":["x","y"]}`, true},
		{"list: one unlisted", `{"a":["x"]}`, ``, `{"a":["x","root"]}`, false},
		{"comma string is whole", `{"a":["x","root"]}`, ``, `{"a":"x,root"}`, false},
		{"comma string listed whole", `{"a":["x,y"]}`, ``, `{"a":"x,y"}`, true},
		{"name case-insensitive", `{"Policies":["x"]}`, ``, `{"POLICIES":"z"}`, false},
		{"number", `{"n":[3]}`, ``, `{"n":3}`, true},
		{"number vs string", `{"n":[3]}`, ``, `{"n":"3"}`, false},
		{"bool", `{"b":[true]}`, ``, `{"b":false}`, false},
		{"object value never matches", `{"o":["x"]}`, ``, `{"o":{"k":"x"}}`, false},
		{"glob suffix", `{"a":["neptune-*"]}`, ``, `{"a":"neptune-prod-read"}`, true},
		{"glob prefix", `{"a":["*-read"]}`, ``, `{"a":"x-write"}`, false},
		{"lone star value is literal", `{"a":["*"]}`, ``, `{"a":"root"}`, false},
		// A comma string may be split by the handler: globs never pass it.
		{"glob vs comma string", `{"a":["neptune-*"]}`, ``, `{"a":"neptune-x,root"}`, false},
		{"glob vs comma string in list", `{"a":["neptune-*"]}`, ``, `{"a":["neptune-x,root"]}`, false},
		{"elements allowed but not whole", `{"a":["x","y"]}`, ``, `{"a":"x,y"}`, false},
		{"glob still matches plain string", `{"a":["neptune-*"]}`, ``, `{"a":"neptune-x"}`, true},
		// Names fold as encoding/json folds them (long s, Kelvin sign).
		{"long s name", `{"policies":["ok"],"*":[]}`, ``, `{"policie\u017f":"root"}`, false},
		{"kelvin name", `{"kind":["ok"],"*":[]}`, ``, `{"\u212aind":"root"}`, false},

		{"denied value", ``, `{"a":["root"]}`, `{"a":"root"}`, false},
		{"denied other value ok", ``, `{"a":["root"]}`, `{"a":"x"}`, true},
		{"denied empty list: any value", ``, `{"a":[]}`, `{"a":"x"}`, false},
		{"denied list element", ``, `{"a":["root"]}`, `{"a":["x","root"]}`, false},
		{"denied star: any parameter", ``, `{"*":[]}`, `{"z":1}`, false},
		{"denied wins over allowed", `{"a":["root"]}`, `{"a":["root"]}`, `{"a":"root"}`, false},
		{"denied name case-insensitive", ``, `{"a":["root"]}`, `{"A":"root"}`, false},
		{"denied comma element", ``, `{"a":["root"]}`, `{"a":"x, root"}`, false},
		{"denied with spaces", ``, `{"a":["legacy"]}`, `{"a":" legacy "}`, false},
		{"denied with spaces in list", ``, `{"a":["legacy"]}`, `{"a":[" legacy"]}`, false},
		{"allowed with spaces is refused", `{"a":["x"]}`, ``, `{"a":[" x"]}`, false},
		{"denied glob comma element", ``, `{"a":["ro*"]}`, `{"a":["x,root"]}`, false},
		{"denied long s name", ``, `{"policies":["root"]}`, `{"policie\u017f":["root"]}`, false},
	}
	for _, c := range cases {
		entry := `"capabilities":["update"]`
		if c.allowed != "" {
			entry += `,"allowed_parameters":` + c.allowed
		}
		if c.denied != "" {
			entry += `,"denied_parameters":` + c.denied
		}
		acl := NewACL(mustParse(t, `{"path":{"x":{`+entry+`}}}`))
		if got := acl.Parameters("x", Update).Allows(body(t, c.data)); got != c.want {
			t.Errorf("%s: Allows(%s) = %v, want %v", c.name, c.data, got, c.want)
		}
	}
}

// Acceptance test 7: policies without either field have no parameter limits.
func TestNoParametersWithoutFields(t *testing.T) {
	acl := NewACL(mustParse(t, `{"path":{"x/*":{"capabilities":["update"]}}}`))
	if p := acl.Parameters("x/y", Create, Update); p != nil {
		t.Fatalf("Parameters = %+v, want nil", p)
	}
	if !acl.Parameters("x/y", Update).Allows(map[string]any{"anything": "goes"}) {
		t.Fatal("nil Parameters must allow")
	}
}

func TestParametersMostSpecificRule(t *testing.T) {
	limited := mustParse(t, `{"path":{"auth/jwt/role/*":{"capabilities":["update"],"allowed_parameters":{"policies":["ok"]}}}}`)
	broad := mustParse(t, `{"path":{"auth/*":{"capabilities":["update"]}}}`)
	exact := mustParse(t, `{"path":{"auth/jwt/role/special":{"capabilities":["update"]}}}`)
	readOnly := mustParse(t, `{"path":{"auth/jwt/role/x":{"capabilities":["read"]}}}`)

	acl := NewACL(broad, limited, exact, readOnly)
	if acl.Parameters("auth/jwt/role/a", Update).Allows(map[string]any{"policies": "root"}) {
		t.Error("broader glob lifted the limit")
	}
	if !acl.Parameters("auth/jwt/role/special", Update).Allows(map[string]any{"policies": "root"}) {
		t.Error("an exact path rule should govern its path")
	}
	// A more specific rule that does not grant the capability does not govern.
	if acl.Parameters("auth/jwt/role/x", Update).Allows(map[string]any{"policies": "root"}) {
		t.Error("read-only exact rule lifted the update limit")
	}
	if !acl.Parameters("auth/other", Update).Allows(map[string]any{"policies": "root"}) {
		t.Error("broad grant elsewhere should be unlimited")
	}
}

func TestParametersMergeAcrossPolicies(t *testing.T) {
	a := mustParse(t, `{"path":{"x":{"capabilities":["update"],"allowed_parameters":{"p":["a"]}}}}`)
	b := mustParse(t, `{"path":{"x":{"capabilities":["update"],"allowed_parameters":{"p":["b"],"q":[]}}}}`)
	none := mustParse(t, `{"path":{"x":{"capabilities":["update"]}}}`)
	acl := NewACL(a, b, none)
	params := acl.Parameters("x", Update)
	for data, want := range map[string]bool{
		`{"p":"a"}`: true, `{"p":"b"}`: true, `{"p":"c"}`: false, `{"q":"z"}`: true, `{"r":1}`: false,
	} {
		if got := params.Allows(body(t, data)); got != want {
			t.Errorf("merged Allows(%s) = %v, want %v", data, got, want)
		}
	}
	// An empty list (any value) in one policy wins over a list in another.
	c := mustParse(t, `{"path":{"x":{"capabilities":["update"],"allowed_parameters":{"p":[]}}}}`)
	if !NewACL(a, c).Parameters("x", Update).Allows(map[string]any{"p": "zzz"}) {
		t.Error("empty list should win in a merge")
	}
}

func TestParametersSurviveTemplating(t *testing.T) {
	p := mustParse(t, `{"path":{"secret/{{identity.entity.name}}/*":{"capabilities":["update"],"denied_parameters":{"k":[]}}}}`)
	tp := p.Templated(func(string) (string, bool) { return "alice", true })
	if NewACL(tp).Parameters("secret/alice/x", Update).Allows(map[string]any{"k": 1}) {
		t.Fatal("templating dropped denied_parameters")
	}
}

func TestParseHCLParameters(t *testing.T) {
	p := mustParse(t, `
path "auth/jwt/role/*" {
  capabilities = ["create", "update"]
  allowed_parameters = {
    "policies" = ["a", "b"]
    "*"        = []
  }
  denied_parameters {
    flag = [true],
    "ttl" = []
  }
}`)
	r := p.Rules[0]
	if len(r.AllowedParameters["policies"]) != 2 || r.AllowedParameters["*"] == nil || len(r.AllowedParameters["*"]) != 0 {
		t.Fatalf("allowed = %#v", r.AllowedParameters)
	}
	if r.DeniedParameters["flag"][0] != true || r.DeniedParameters["ttl"] == nil {
		t.Fatalf("denied = %#v", r.DeniedParameters)
	}
	// HCL and JSON render to the same stored document.
	j := mustParse(t, `{"path":{"auth/jwt/role/*":{"capabilities":["create","update"],
	  "allowed_parameters":{"policies":["a","b"],"*":[]},"denied_parameters":{"flag":[true],"ttl":[]}}}}`)
	hd, _ := p.Document()
	jd, _ := j.Document()
	if string(hd) != string(jd) {
		t.Fatalf("HCL %s != JSON %s", hd, jd)
	}

	for _, bad := range []string{
		`path "x" { capabilities = ["read"] capabilities = ["list"] }`,
		`path "x" { allowed_parameters = { "a" = [] } }`,
		`path "x" { capabilities = ["update"] allowed_parameters = { "a" = [1] } }`,
		`path "x" { capabilities = ["update"] allowed_parameters = { "a" = [] "a" = ["b"] } }`,
		`path "x" { capabilities = ["update"] min_wrapping_ttl = "1h" }`,
		`path "x" { capabilities = ["update"] required_parameters = [1] }`,
		`path "x" { capabilities = ["update"] allowed_parameters = { "a" = [`,
	} {
		if _, err := ParseDocument("p", []byte(bad)); err == nil {
			t.Errorf("parsed %q, want error", bad)
		} else if !strings.Contains(err.Error(), "policy:") {
			t.Errorf("%q: error %v", bad, err)
		}
	}
}

func TestRequiredParameters(t *testing.T) {
	p := mustParse(t, `{"path":{"auth/jwt/role/*":{"capabilities":["create","update"],"required_parameters":["bound_claims"]}}}`)
	params := NewACL(p).Parameters("auth/jwt/role/a", Create, Update)
	for data, want := range map[string]bool{
		`{}`:                              false,
		`{"policies":["x"]}`:              false,
		`{"bound_claims":{"sub":"x"}}`:    true,
		`{"BOUND_CLAIMS":{}}`:             true,
		`{"bound_claim\u017f":{}}`:        true,  // decodes as bound_claims, so it is present
		`{"bound_claims":null,"other":1}`: false, // null reads as "not sent"
		`{"bound_claims":{}}`:             true,  // presence only, as in Vault
	} {
		if got := params.Allows(body(t, data)); got != want {
			t.Errorf("Allows(%s) = %v, want %v", data, got, want)
		}
	}
	// Merged as a union across policies on the same path.
	q := mustParse(t, `{"path":{"auth/jwt/role/*":{"capabilities":["update"],"required_parameters":["token_ttl"]}}}`)
	merged := NewACL(p, q).Parameters("auth/jwt/role/a", Update)
	if merged.Allows(body(t, `{"bound_claims":{}}`)) || !merged.Allows(body(t, `{"bound_claims":{},"token_ttl":"1h"}`)) {
		t.Error("required_parameters should merge as a union")
	}
	// HCL form, and it reads back.
	h := mustParse(t, `path "x" {
  capabilities = ["update"]
  required_parameters = ["a", "b"]
}`)
	doc, _ := h.Document()
	if !strings.Contains(string(doc), `"required_parameters":["a","b"]`) {
		t.Fatalf("document %s", doc)
	}
}
