package policy

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// ParseHCL parses a HashiCorp-style HCL policy document into a [Policy]. The
// supported grammar is the policy subset (not full HCL):
//
//	# or // or /* */ comments
//	path "<pattern>" {
//	  capabilities = ["read", "list"]
//	  allowed_parameters = {          # optional; "= " may be omitted
//	    "policies" = ["app-read"]
//	    "*"        = []
//	  }
//	  denied_parameters = { "ttl" = [] }  # optional
//	  required_parameters = ["bound_claims"]  # optional
//	}
//
// Parameter values are strings or the booleans true/false; numbers are not
// supported in HCL (use the JSON form).
//
// Full HCL (heredocs, interpolation, etc.) is out of scope; docs/DECISIONS.md
// (D-011) records the choice and notes hashicorp/hcl as a future option.
func ParseHCL(name string, data []byte) (*Policy, error) {
	toks, err := lexHCL(string(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedPolicy, err)
	}
	p := &Policy{Name: name}
	tp := &tokenParser{toks: toks}

	for !tp.atEnd() {
		if err := tp.expectKeyword("path"); err != nil {
			return nil, wrapMalformed(err)
		}
		pattern, err := tp.expect(tokString)
		if err != nil {
			return nil, wrapMalformed(err)
		}
		if _, err := tp.expect(tokLBrace); err != nil {
			return nil, wrapMalformed(err)
		}
		rule, err := tp.pathBody(pattern)
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, rule)
	}

	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].Path < p.Rules[j].Path })
	return p, nil
}

func wrapMalformed(err error) error {
	return fmt.Errorf("%w: %v", ErrMalformedPolicy, err)
}

// --- lexer ---

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokLBrace
	tokRBrace
	tokLBracket
	tokRBracket
	tokEquals
	tokComma
)

type token struct {
	kind tokenKind
	val  string
}

func lexHCL(s string) ([]token, error) {
	var toks []token
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		c := runes[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '#':
			i = skipLine(runes, i)
		case c == '/' && i+1 < len(runes) && runes[i+1] == '/':
			i = skipLine(runes, i)
		case c == '/' && i+1 < len(runes) && runes[i+1] == '*':
			var err error
			if i, err = skipBlockComment(runes, i); err != nil {
				return nil, err
			}
		case c == '"':
			str, next, err := lexString(runes, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{tokString, str})
			i = next
		case c == '{':
			toks = append(toks, token{tokLBrace, "{"})
			i++
		case c == '}':
			toks = append(toks, token{tokRBrace, "}"})
			i++
		case c == '[':
			toks = append(toks, token{tokLBracket, "["})
			i++
		case c == ']':
			toks = append(toks, token{tokRBracket, "]"})
			i++
		case c == '=':
			toks = append(toks, token{tokEquals, "="})
			i++
		case c == ',':
			toks = append(toks, token{tokComma, ","})
			i++
		case isIdentStart(c):
			ident, next := lexIdent(runes, i)
			toks = append(toks, token{tokIdent, ident})
			i = next
		default:
			return nil, fmt.Errorf("unexpected character %q", string(c))
		}
	}
	return append(toks, token{tokEOF, ""}), nil
}

func skipLine(runes []rune, i int) int {
	for i < len(runes) && runes[i] != '\n' {
		i++
	}
	return i
}

func skipBlockComment(runes []rune, i int) (int, error) {
	i += 2 // consume "/*"
	for i+1 < len(runes) {
		if runes[i] == '*' && runes[i+1] == '/' {
			return i + 2, nil
		}
		i++
	}
	return 0, fmt.Errorf("unterminated block comment")
}

func lexString(runes []rune, i int) (string, int, error) {
	i++ // consume opening quote
	var b strings.Builder
	for i < len(runes) {
		c := runes[i]
		switch c {
		case '"':
			return b.String(), i + 1, nil
		case '\\':
			if i+1 >= len(runes) {
				return "", 0, fmt.Errorf("unterminated string escape")
			}
			b.WriteRune(runes[i+1])
			i += 2
		case '\n':
			return "", 0, fmt.Errorf("unterminated string")
		default:
			b.WriteRune(c)
			i++
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

func lexIdent(runes []rune, i int) (string, int) {
	start := i
	for i < len(runes) && isIdentPart(runes[i]) {
		i++
	}
	return string(runes[start:i]), i
}

func isIdentStart(c rune) bool { return unicode.IsLetter(c) || c == '_' }
func isIdentPart(c rune) bool  { return isIdentStart(c) || unicode.IsDigit(c) || c == '-' }

// --- parser ---

type tokenParser struct {
	toks []token
	pos  int
}

func (p *tokenParser) atEnd() bool { return p.toks[p.pos].kind == tokEOF }

func (p *tokenParser) expect(kind tokenKind) (string, error) {
	t := p.toks[p.pos]
	if t.kind != kind {
		return "", fmt.Errorf("unexpected token %q", t.val)
	}
	p.pos++
	return t.val, nil
}

func (p *tokenParser) expectKeyword(word string) error {
	t := p.toks[p.pos]
	if t.kind != tokIdent || t.val != word {
		return fmt.Errorf("expected %q, got %q", word, t.val)
	}
	p.pos++
	return nil
}

func (p *tokenParser) capabilityList() ([]Capability, error) {
	if _, err := p.expect(tokLBracket); err != nil {
		return nil, wrapMalformed(err)
	}
	var caps []Capability
	for {
		if p.toks[p.pos].kind == tokRBracket {
			p.pos++
			return caps, nil
		}
		val, err := p.expect(tokString)
		if err != nil {
			return nil, wrapMalformed(err)
		}
		c := Capability(val)
		if !validCapabilities[c] {
			return nil, fmt.Errorf("%w: %q", ErrUnknownCapability, val)
		}
		caps = append(caps, c)
		// Optional comma between elements.
		if p.toks[p.pos].kind == tokComma {
			p.pos++
		}
	}
}

// pathBody parses the attributes of a path block up to and including its
// closing brace. capabilities is required; each attribute may appear once.
func (p *tokenParser) pathBody(pattern string) (Rule, error) {
	rule := Rule{Path: pattern}
	seen := map[string]bool{}
	for p.toks[p.pos].kind != tokRBrace {
		key, err := p.expect(tokIdent)
		if err != nil {
			return Rule{}, wrapMalformed(err)
		}
		if seen[key] {
			return Rule{}, wrapMalformed(fmt.Errorf("duplicate %q", key))
		}
		seen[key] = true
		switch key {
		case "capabilities":
			if _, err := p.expect(tokEquals); err != nil {
				return Rule{}, wrapMalformed(err)
			}
			if rule.Capabilities, err = p.capabilityList(); err != nil {
				return Rule{}, err
			}
		case "allowed_parameters", "denied_parameters":
			params, err := p.parameterMap()
			if err != nil {
				return Rule{}, err
			}
			if key == "allowed_parameters" {
				rule.AllowedParameters = params
			} else {
				rule.DeniedParameters = params
			}
		case "required_parameters":
			if _, err := p.expect(tokEquals); err != nil {
				return Rule{}, wrapMalformed(err)
			}
			if rule.RequiredParameters, err = p.stringList(); err != nil {
				return Rule{}, err
			}
		default:
			return Rule{}, wrapMalformed(fmt.Errorf("unsupported attribute %q", key))
		}
	}
	p.pos++ // consume "}"
	if !seen["capabilities"] {
		return Rule{}, wrapMalformed(fmt.Errorf("path %q: missing capabilities", pattern))
	}
	return rule, nil
}

// parameterMap parses `[=] { "name" = [values...] ... }`. Entries may be
// separated by commas or just whitespace. A name is a string or identifier.
func (p *tokenParser) parameterMap() (map[string][]any, error) {
	if p.toks[p.pos].kind == tokEquals {
		p.pos++
	}
	if _, err := p.expect(tokLBrace); err != nil {
		return nil, wrapMalformed(err)
	}
	params := map[string][]any{}
	for {
		t := p.toks[p.pos]
		if t.kind == tokRBrace {
			p.pos++
			return params, nil
		}
		if t.kind != tokString && t.kind != tokIdent {
			return nil, wrapMalformed(fmt.Errorf("unexpected token %q", t.val))
		}
		p.pos++
		if _, dup := params[t.val]; dup {
			return nil, wrapMalformed(fmt.Errorf("duplicate parameter %q", t.val))
		}
		if _, err := p.expect(tokEquals); err != nil {
			return nil, wrapMalformed(err)
		}
		values, err := p.valueList()
		if err != nil {
			return nil, err
		}
		params[t.val] = values
		if p.toks[p.pos].kind == tokComma {
			p.pos++
		}
	}
}

// valueList parses `[ v, ... ]` where each v is a string or true/false. The
// result is never nil, so an empty list means "any value".
func (p *tokenParser) valueList() ([]any, error) {
	if _, err := p.expect(tokLBracket); err != nil {
		return nil, wrapMalformed(err)
	}
	values := []any{}
	for {
		t := p.toks[p.pos]
		switch {
		case t.kind == tokRBracket:
			p.pos++
			return values, nil
		case t.kind == tokString:
			values = append(values, t.val)
		case t.kind == tokIdent && (t.val == "true" || t.val == "false"):
			values = append(values, t.val == "true")
		default:
			return nil, wrapMalformed(fmt.Errorf("unexpected value %q", t.val))
		}
		p.pos++
		if p.toks[p.pos].kind == tokComma {
			p.pos++
		}
	}
}

// stringList parses `[ "a", "b" ]`.
func (p *tokenParser) stringList() ([]string, error) {
	if _, err := p.expect(tokLBracket); err != nil {
		return nil, wrapMalformed(err)
	}
	out := []string{}
	for {
		if p.toks[p.pos].kind == tokRBracket {
			p.pos++
			return out, nil
		}
		v, err := p.expect(tokString)
		if err != nil {
			return nil, wrapMalformed(err)
		}
		out = append(out, v)
		if p.toks[p.pos].kind == tokComma {
			p.pos++
		}
	}
}
