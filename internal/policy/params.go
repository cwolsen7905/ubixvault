package policy

import (
	"fmt"
	"strings"
)

// validateParameters checks an allowed_parameters or denied_parameters map
// from a policy document. Values must be lists of strings, numbers or booleans.
// A null list is refused rather than read as "any value": "any value" is
// written as an empty list, and a null is more likely a mistake.
func validateParameters(field string, params map[string][]any) error {
	for key, values := range params {
		if values == nil {
			return fmt.Errorf("%w: %s %q: use [] for any value, not null", ErrMalformedPolicy, field, key)
		}
		for _, v := range values {
			switch v.(type) {
			case string, float64, bool:
			default:
				return fmt.Errorf("%w: %s %q: values must be strings, numbers or booleans", ErrMalformedPolicy, field, key)
			}
		}
	}
	return nil
}

// Parameters are the parameter limits that govern one write request: those of
// the most specific rule granting the capability, merged across policies that
// share that path. Keys are lower-cased. A nil *Parameters limits nothing.
type Parameters struct {
	allowed map[string][]any
	denied  map[string][]any
}

// Parameters returns the limits on a request's parameters for any of caps on
// path, or nil when there are none.
//
// Capability evaluation is unchanged ([ACL.Allows]: any matching rule may
// grant). Parameter limits come from the most specific matching rule that
// grants one of caps, as in Vault: an exact path beats a glob, and a longer
// glob beats a shorter one. So a broader grant (say "auth/*") does not lift
// the limits a policy sets on "auth/jwt/role/*". Rules for that same path in
// several policies are merged the way Vault merges them: a rule without limits
// does not lift another's, and an empty value list (any value) wins over a
// non-empty one.
func (a *ACL) Parameters(path string, caps ...Capability) *Parameters {
	best := ""
	found := false
	for _, r := range a.rules {
		if !matchPath(r.Path, path) || !grantsAny(r.Capabilities, caps) {
			continue
		}
		if !found || moreSpecific(r.Path, best) {
			best, found = r.Path, true
		}
	}
	if !found {
		return nil
	}
	var allowed, denied map[string][]any
	for _, r := range a.rules {
		if r.Path != best || !grantsAny(r.Capabilities, caps) {
			continue
		}
		allowed = mergeParameters(allowed, r.AllowedParameters)
		denied = mergeParameters(denied, r.DeniedParameters)
	}
	if len(allowed) == 0 && len(denied) == 0 {
		return nil
	}
	return &Parameters{allowed: allowed, denied: denied}
}

func grantsAny(have, want []Capability) bool {
	for _, c := range want {
		if hasCapability(have, c) {
			return true
		}
	}
	return false
}

// moreSpecific reports whether pattern a is more specific than b: an exact
// path beats a glob; between globs the longer prefix wins.
func moreSpecific(a, b string) bool {
	aGlob, bGlob := strings.HasSuffix(a, "*"), strings.HasSuffix(b, "*")
	if aGlob != bGlob {
		return !aGlob
	}
	return len(a) > len(b)
}

// mergeParameters folds src into dst (lower-casing keys) the way Vault merges
// one path's limits across policies.
func mergeParameters(dst, src map[string][]any) map[string][]any {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string][]any, len(src))
	}
	for key, values := range src {
		key = strings.ToLower(key)
		existing, ok := dst[key]
		if len(values) == 0 || (ok && len(existing) == 0) {
			dst[key] = []any{}
			continue
		}
		dst[key] = append(append([]any{}, existing...), values...)
	}
	return dst
}

// Allows reports whether a request with the given body parameters satisfies
// the limits, following Vault:
//
//   - A request without parameters is allowed.
//   - denied_parameters: a "*" key refuses any request with parameters; a
//     named parameter is refused if its value is listed, or always when its
//     list is empty. Denial wins over allowed_parameters.
//   - allowed_parameters: when set, a parameter it does not name is refused
//     unless "*" is a key. A named parameter must have a listed value, or
//     any value when its list is empty, even when "*" is present.
//
// A list value is allowed only if every element is, and denied if any element
// is. A comma-separated string is a single value: it is compared whole. String
// values in the policy may glob with a leading or trailing "*", as in Vault.
// Parameter names match case-insensitively.
func (p *Parameters) Allows(data map[string]any) bool {
	if p == nil || len(data) == 0 {
		return true
	}
	if len(p.denied) > 0 {
		if _, ok := p.denied["*"]; ok {
			return false
		}
		for name, value := range data {
			if list, ok := p.denied[strings.ToLower(name)]; ok && anyListed(value, list) {
				return false
			}
		}
	}
	if len(p.allowed) == 0 {
		return true
	}
	_, allowAll := p.allowed["*"]
	for name, value := range data {
		list, ok := p.allowed[strings.ToLower(name)]
		if !ok {
			if !allowAll {
				return false
			}
			continue
		}
		if !allListed(value, list) {
			return false
		}
	}
	return true
}

// allListed reports whether value is allowed by list: always for an empty
// list; for a list value, only if every element is listed.
func allListed(value any, list []any) bool {
	if len(list) == 0 {
		return true
	}
	if elems, ok := value.([]any); ok {
		for _, e := range elems {
			if !inList(e, list) {
				return false
			}
		}
		return true
	}
	return inList(value, list)
}

// anyListed reports whether value is denied by list: always for an empty list;
// for a list value, if any element is listed.
func anyListed(value any, list []any) bool {
	if len(list) == 0 {
		return true
	}
	if elems, ok := value.([]any); ok {
		for _, e := range elems {
			if inList(e, list) {
				return true
			}
		}
		return false
	}
	return inList(value, list)
}

// inList reports whether a scalar value equals an entry of list. Strings
// compare with Vault's globbing; other types compare by value and type, so
// the string "1" never matches the number 1. Objects and nested lists never
// match.
func inList(value any, list []any) bool {
	for _, item := range list {
		switch iv := item.(type) {
		case string:
			if s, ok := value.(string); ok && globMatch(iv, s) {
				return true
			}
		case float64:
			if f, ok := value.(float64); ok && f == iv {
				return true
			}
		case bool:
			if b, ok := value.(bool); ok && b == iv {
				return true
			}
		}
	}
	return false
}

// globMatch is Vault's GlobbedStringsMatch: "*x*" contains, "*x" suffix, "x*"
// prefix, otherwise equality. A pattern shorter than two characters (including
// a lone "*") only matches itself.
func globMatch(pattern, s string) bool {
	if len(pattern) < 2 {
		return pattern == s
	}
	prefix, suffix := strings.HasPrefix(pattern, "*"), strings.HasSuffix(pattern, "*")
	switch {
	case prefix && suffix:
		return strings.Contains(s, pattern[1:len(pattern)-1])
	case prefix:
		return strings.HasSuffix(s, pattern[1:])
	case suffix:
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	default:
		return s == pattern
	}
}
