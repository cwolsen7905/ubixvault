package api

import (
	"errors"
	"net/http"
	"time"
)

// Helpers for auth-method role writes, which follow Vault: every field is
// optional, and a write to an existing role changes only the fields it sends.

// errTTLOverMax refuses a role whose token TTL would exceed its token_max_ttl.
var errTTLOverMax = errors.New("token_ttl must not exceed token_max_ttl")

// optionalDuration parses a duration field that may be absent (nil). It writes
// a 400 and returns false when the value is invalid.
func optionalDuration(w http.ResponseWriter, d *vaultDuration, field string) (*time.Duration, bool) {
	if d == nil {
		return nil, true
	}
	v, ok := parseOptionalDuration(w, string(*d), field)
	if !ok {
		return nil, false
	}
	return &v, true
}

// firstSet returns the first non-nil value: the current Vault name of a field
// before its older alias (token_policies before policies).
func firstSet[T any](vals ...*T) *T {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// apply sets *dst to *src when src was sent.
func apply[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

// applyList sets *dst to the list in src when src was sent.
func applyList(dst *[]string, src *stringList) {
	if src != nil {
		*dst = []string(*src)
	}
}

// checkTTL refuses a token TTL over a non-zero maximum.
func checkTTL(ttl, maxTTL time.Duration) error {
	if maxTTL > 0 && ttl > maxTTL {
		return errTTLOverMax
	}
	return nil
}

// writeRoleUpdateError answers a failed role update: 400 for errTTLOverMax,
// otherwise the method's own error writer.
func writeRoleUpdateError(w http.ResponseWriter, err error, methodErr func(http.ResponseWriter, error)) {
	if errors.Is(err, errTTLOverMax) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	methodErr(w, err)
}
