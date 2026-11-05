package policy

import (
	"fmt"
	"strings"
	"unicode"
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

// validateRequired checks a required_parameters list: non-empty names, and no
// "*" (Vault gives it no meaning there, so it is more likely a mistake).
func validateRequired(names []string) error {
	for _, n := range names {
		if strings.TrimSpace(n) == "" || n == "*" {
			return fmt.Errorf("%w: required_parameters: %q is not a parameter name", ErrMalformedPolicy, n)
		}
	}
	return nil
}

// Parameters are the parameter limits that govern one write request: those of
// the most specific rule granting the capability, merged across policies that
// share that path. Keys are folded with [foldName]. A nil *Parameters limits
// nothing.
type Parameters struct {
	allowed  map[string][]any
	denied   map[string][]any
	required map[string]bool
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
	var required map[string]bool
	for _, r := range a.rules {
		if r.Path != best || !grantsAny(r.Capabilities, caps) {
			continue
		}
		allowed = mergeParameters(allowed, r.AllowedParameters)
		denied = mergeParameters(denied, r.DeniedParameters)
		for _, n := range r.RequiredParameters { // merged as a union, as in Vault
			if required == nil {
				required = map[string]bool{}
			}
			required[foldName(n)] = true
		}
	}
	if len(allowed) == 0 && len(denied) == 0 && len(required) == 0 {
		return nil
	}
	return &Parameters{allowed: allowed, denied: denied, required: required}
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

// mergeParameters folds src into dst (folding keys with [foldName]) the way
// Vault merges one path's limits across policies.
func mergeParameters(dst, src map[string][]any) map[string][]any {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string][]any, len(src))
	}
	for key, values := range src {
		key = foldName(key)
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
//   - required_parameters: each listed name must be sent with a non-null
//     value, merged across policies as a union. This is checked first, so it
//     also refuses a request without parameters. It guarantees presence only:
//     an empty value such as {} or "" satisfies it, as in Vault. (null does
//     not, because handlers treat null as "not sent".)
//   - Otherwise a request without parameters is allowed.
//   - denied_parameters: a "*" key refuses any request with parameters; a
//     named parameter is refused if its value is listed, or always when its
//     list is empty. Denial wins over allowed_parameters.
//   - allowed_parameters: when set, a parameter it does not name is refused
//     unless "*" is a key. A named parameter must have a listed value, or
//     any value when its list is empty, even when "*" is present.
//
// A list value is allowed only if every element is, and denied if any element
// is. String values in the policy may glob with a leading or trailing "*", as
// in Vault.
//
// A string containing a comma may be split into a list by the handler (role
// policies are), so the check must not judge it differently: it is allowed
// only if it equals a listed value exactly — globs never apply to it — and is
// denied if the whole string or any comma-separated element is denied.
//
// Parameter names match the way the handler's JSON decoder matches them (see
// [foldName]), so a name the decoder treats as "policies" is limited as one.
func (p *Parameters) Allows(data map[string]any) bool {
	if p == nil {
		return true
	}
	if len(p.required) > 0 {
		present := make(map[string]bool, len(data))
		for name, value := range data {
			if value == nil {
				continue // handlers read null as "not sent", so it does not count
			}
			present[foldName(name)] = true
		}
		for name := range p.required {
			if !present[name] {
				return false
			}
		}
	}
	if len(data) == 0 {
		return true
	}
	if len(p.denied) > 0 {
		if _, ok := p.denied["*"]; ok {
			return false
		}
		for name, value := range data {
			if list, ok := p.denied[foldName(name)]; ok && anyListed(value, list) {
				return false
			}
		}
	}
	if len(p.allowed) == 0 {
		return true
	}
	_, allowAll := p.allowed["*"]
	for name, value := range data {
		list, ok := p.allowed[foldName(name)]
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
			if !allowedScalar(e, list) {
				return false
			}
		}
		return true
	}
	return allowedScalar(value, list)
}

// allowedScalar reports whether one scalar is listed. A string with a comma
// must equal a listed string exactly (see [Parameters.Allows]).
func allowedScalar(value any, list []any) bool {
	if s, ok := value.(string); ok && strings.Contains(s, ",") {
		for _, item := range list {
			if is, ok := item.(string); ok && is == s {
				return true
			}
		}
		return false
	}
	return inList(value, list)
}

// deniedScalar reports whether one scalar is denied. A string is judged both
// as sent and as a handler may normalize it — trimmed, and split at commas
// into trimmed elements — so whitespace or commas cannot carry a denied value
// past the check. (On the allowed side, those forms are simply not listed, so
// they are refused: no normalization is needed there.)
func deniedScalar(value any, list []any) bool {
	if inList(value, list) {
		return true
	}
	s, ok := value.(string)
	if !ok {
		return false
	}
	if inList(strings.TrimSpace(s), list) {
		return true
	}
	for _, part := range strings.Split(s, ",") {
		if inList(strings.TrimSpace(part), list) {
			return true
		}
	}
	return false
}

// foldName canonicalizes a parameter name so that two names are equal exactly
// when bytes.EqualFold reports them equal, which is how encoding/json matches
// a body key to a struct field: each rune is replaced by the smallest rune in
// its Unicode simple-folding orbit. So "POLICIES", "policies" and "policieſ"
// (long s) all fold to the same key.
func foldName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}

// anyListed reports whether value is denied by list: always for an empty list;
// for a list value, if any element is listed.
func anyListed(value any, list []any) bool {
	if len(list) == 0 {
		return true
	}
	if elems, ok := value.([]any); ok {
		for _, e := range elems {
			if deniedScalar(e, list) {
				return true
			}
		}
		return false
	}
	return deniedScalar(value, list)
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
