package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/policy"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// tokenHeader is the request header carrying the client token.
const tokenHeader = "X-Vault-Token" //nolint:gosec // G101: this is an HTTP header name, not a credential

// ctxKey is an unexported context key type.
type ctxKey int

const tokenCtxKey ctxKey = iota

// authenticate wraps a handler so it runs only for a request that is both
// authenticated (a valid X-Vault-Token) and authorized (the token's policies
// permit the operation on the path). The authenticated token is placed on the
// request context.
func (h *Handler) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(tokenHeader)
		if id == "" {
			writeError(w, http.StatusUnauthorized, "missing authentication token")
			return
		}

		tok, err := h.tokens.Lookup(r.Context(), id)
		switch {
		case errors.Is(err, barrier.ErrSealed):
			writeError(w, http.StatusServiceUnavailable, "vault is sealed")
			return
		case errors.Is(err, token.ErrTokenNotFound):
			writeError(w, http.StatusForbidden, "permission denied")
			return
		case err != nil:
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		allowed, err := h.authorize(r.Context(), tok, r.Method, apiPath(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		ctx := context.WithValue(r.Context(), tokenCtxKey, tok)
		next(w, r.WithContext(ctx))
	}
}

// apiPath is the policy-space path for a request: the URL path without the
// "/v1/" version prefix (e.g. "secret/data/app").
func apiPath(r *http.Request) string {
	return strings.TrimPrefix(r.URL.Path, "/v1/")
}

// authorize reports whether tok may perform method on path. Root tokens are
// always permitted; others are evaluated against the ACL formed by their
// policies. HTTP methods map to capabilities: GET→read, LIST→list,
// DELETE→delete, POST/PUT→create or update.
func (h *Handler) authorize(ctx context.Context, tok *token.Token, method, path string) (bool, error) {
	if tok.IsRoot() {
		return true, nil
	}

	var policies []*policy.Policy
	for _, name := range tok.Policies {
		p, err := h.policies.Get(ctx, name)
		switch {
		case errors.Is(err, policy.ErrPolicyNotFound):
			continue // a named-but-missing policy grants nothing
		case err != nil:
			return false, err
		}
		policies = append(policies, p)
	}
	acl := policy.NewACL(policies...)

	switch method {
	case http.MethodGet:
		return acl.Allows(path, policy.Read), nil
	case "LIST":
		return acl.Allows(path, policy.List), nil
	case http.MethodDelete:
		return acl.Allows(path, policy.Delete), nil
	case http.MethodPost, http.MethodPut:
		return acl.Allows(path, policy.Create) || acl.Allows(path, policy.Update), nil
	default:
		return false, nil
	}
}
