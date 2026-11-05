package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// capabilitiesRequest is the body of sys/capabilities-self and
// sys/capabilities. paths is Vault's current field; path is the older one.
type capabilitiesRequest struct {
	Paths stringList `json:"paths"`
	Path  stringList `json:"path"`
	Token string     `json:"token"` // sys/capabilities only
}

// capabilitiesSelf reports what the calling token may do on each path. Every
// token may call it, as under Vault's default policy.
func (h *Handler) capabilitiesSelf(w http.ResponseWriter, r *http.Request) {
	var req capabilitiesRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Token != "" {
		writeError(w, http.StatusBadRequest, "token is not accepted here; use sys/capabilities")
		return
	}
	tok, ok := tokenFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "no token on request")
		return
	}
	h.writeCapabilities(w, r.Context(), tok, req)
}

// capabilities reports what another token may do on each path. It needs an
// ACL grant on sys/capabilities, like any other endpoint.
func (h *Handler) capabilities(w http.ResponseWriter, r *http.Request) {
	var req capabilitiesRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	tok, err := h.tokens.Lookup(r.Context(), req.Token)
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
		return
	case errors.Is(err, token.ErrTokenNotFound), errors.Is(err, token.ErrTokenExpired):
		writeError(w, http.StatusBadRequest, "invalid token")
		return
	case err != nil:
		writeInternal(w, err)
		return
	}
	h.writeCapabilities(w, r.Context(), tok, req)
}

// writeCapabilities answers in Vault's shape: one key per path, plus
// "capabilities" when a single path was asked, both at the top level and
// under "data" (Vault's clients read either).
func (h *Handler) writeCapabilities(w http.ResponseWriter, ctx context.Context, tok *token.Token, req capabilitiesRequest) {
	paths := req.Paths
	if len(paths) == 0 {
		paths = req.Path
	}
	if len(paths) == 0 {
		writeError(w, http.StatusBadRequest, "paths is required")
		return
	}
	out := map[string]any{}
	for _, p := range paths {
		caps, err := h.capabilitiesOn(ctx, tok, strings.TrimPrefix(p, "/"))
		if err != nil {
			writeInternal(w, err)
			return
		}
		out[p] = caps
		if len(paths) == 1 {
			out["capabilities"] = caps
		}
	}
	body := map[string]any{"data": out}
	for k, v := range out {
		body[k] = v
	}
	writeJSON(w, http.StatusOK, body)
}

// capabilitiesOn is what tok may do on path, mirroring authorize: root gets
// ["root"]; the built-in self paths and the token's own cubbyhole report the
// capabilities Vault's default policy gives them, merged with any ACL grant.
func (h *Handler) capabilitiesOn(ctx context.Context, tok *token.Token, path string) ([]string, error) {
	if tok.IsRoot() {
		return []string{"root"}, nil
	}
	acl, err := h.aclFor(ctx, tok)
	if err != nil {
		return nil, err
	}
	caps := acl.Capabilities(path)
	builtin := builtinCapabilities(path)
	if len(builtin) == 0 {
		return caps, nil
	}
	set := map[string]bool{}
	for _, c := range builtin {
		set[c] = true
	}
	for _, c := range caps {
		if c != "deny" { // authorize lets these through whatever the ACL says
			set[c] = true
		}
	}
	merged := make([]string, 0, len(set))
	for c := range set {
		merged = append(merged, c)
	}
	sort.Strings(merged)
	return merged, nil
}

// builtinCapabilities are the grants authorize makes without an ACL, written
// as Vault's default policy writes them.
func builtinCapabilities(path string) []string {
	switch {
	case path == cubbyholeMountPrefix || strings.HasPrefix(path, cubbyholeMountPrefix+"/"):
		return []string{"create", "delete", "list", "read", "update"}
	case path == "auth/token/lookup-self":
		return []string{"read"}
	case selfTokenPaths[path]:
		return []string{"update"}
	}
	return nil
}
