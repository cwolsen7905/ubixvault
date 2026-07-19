package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// tokenHeader is the request header carrying the client token.
const tokenHeader = "X-Vault-Token" //nolint:gosec // G101: this is an HTTP header name, not a credential

// ctxKey is an unexported context key type.
type ctxKey int

const tokenCtxKey ctxKey = iota

// authenticate wraps a handler so it runs only for an authenticated request.
// The token is taken from the X-Vault-Token header, looked up, and placed on the
// request context.
//
// Authorization is currently coarse: only root tokens are permitted. Fine-
// grained ACL policy evaluation lands in a follow-up; this middleware is where
// that check will go.
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

		if !tok.IsRoot() {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		ctx := context.WithValue(r.Context(), tokenCtxKey, tok)
		next(w, r.WithContext(ctx))
	}
}
