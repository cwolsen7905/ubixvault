package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/policy"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// policyWrite creates or replaces an ACL policy. The request body is the policy
// document (JSON): {"path": {"<pattern>": {"capabilities": [...]}}}.
func (h *Handler) policyWrite(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	p, err := policy.ParseDocument(r.PathValue("name"), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.policies.Set(r.Context(), p); err != nil {
		writePolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) policyRead(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := h.policies.Get(r.Context(), name)
	if err != nil {
		writePolicyError(w, err)
		return
	}
	doc, err := p.Document()
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeData(w, map[string]any{"name": name, "policy": json.RawMessage(doc)})
}

func (h *Handler) policyDelete(w http.ResponseWriter, r *http.Request) {
	if err := h.policies.Delete(r.Context(), r.PathValue("name")); err != nil {
		writePolicyError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) policyList(w http.ResponseWriter, r *http.Request) {
	names, err := h.policies.List(r.Context())
	if err != nil {
		writePolicyError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

// tokenCreate issues a new token with the requested policies.
func (h *Handler) tokenCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policies []string `json:"policies"`
		TTL      string   `json:"ttl"` // optional duration; empty uses the default TTL
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	var (
		tok *token.Token
		err error
	)
	if req.TTL != "" {
		ttl, perr := time.ParseDuration(req.TTL)
		if perr != nil || ttl <= 0 {
			writeError(w, http.StatusBadRequest, "ttl must be a positive duration (e.g. \"1h\")")
			return
		}
		tok, err = h.tokens.CreateWithTTL(r.Context(), req.Policies, ttl)
	} else {
		tok, err = h.tokens.Create(r.Context(), req.Policies)
	}
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenAuthResponse(tok))
}

// renewSelf extends the lifetime of the calling token.
func (h *Handler) renewSelf(w http.ResponseWriter, r *http.Request) {
	tok, ok := tokenFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "no token on request")
		return
	}
	var req struct {
		Increment string `json:"increment"` // optional duration; empty uses the default TTL
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	var ttl time.Duration
	if req.Increment != "" {
		d, err := time.ParseDuration(req.Increment)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "increment must be a positive duration")
			return
		}
		ttl = d
	}
	renewed, err := h.tokens.Renew(r.Context(), tok.ID, ttl)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenAuthResponse(renewed))
}

// lookupSelf describes the calling token, in the shape of Vault's
// auth/token/lookup-self. identity_policies lists what the token's identity
// entity contributes on top of its own policies.
func (h *Handler) lookupSelf(w http.ResponseWriter, r *http.Request) {
	tok, ok := tokenFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "no token on request")
		return
	}
	identityPolicies := []string{}
	if h.identity != nil && tok.EntityID != "" {
		p, err := h.identity.PoliciesFor(r.Context(), tok.EntityID)
		if err != nil {
			writeInternal(w, err)
			return
		}
		identityPolicies = append(identityPolicies, p...)
	}
	var (
		ttl        int
		expireTime any // null for a non-expiring token, as in Vault
	)
	if !tok.ExpiresAt.IsZero() {
		if d := time.Until(tok.ExpiresAt); d > 0 {
			ttl = int(d.Seconds())
		}
		expireTime = tok.ExpiresAt.UTC().Format(time.RFC3339)
	}
	policies := tok.Policies
	if policies == nil {
		policies = []string{}
	}
	writeData(w, map[string]any{
		"id":                tok.ID,
		"policies":          policies,
		"identity_policies": identityPolicies,
		"entity_id":         tok.EntityID,
		"creation_time":     tok.CreatedTime.Unix(),
		"issue_time":        tok.CreatedTime.UTC().Format(time.RFC3339),
		"expire_time":       expireTime,
		"ttl":               ttl,
		"renewable":         !tok.ExpiresAt.IsZero(),
		"type":              "service",
	})
}

// tokenAuthResponse builds the {"auth": ...} body for a token, including its
// remaining lease in seconds (0 for a non-expiring token).
func tokenAuthResponse(tok *token.Token) map[string]any {
	var leaseSeconds int
	if !tok.ExpiresAt.IsZero() {
		if d := time.Until(tok.ExpiresAt); d > 0 {
			leaseSeconds = int(d.Seconds())
		}
	}
	return map[string]any{
		"auth": map[string]any{
			"client_token":   tok.ID,
			"policies":       tok.Policies,
			"entity_id":      tok.EntityID,
			"lease_duration": leaseSeconds,
		},
	}
}

// readBody reads a size-capped request body.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return nil, false
	}
	return body, true
}

func writePolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policy.ErrPolicyNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, policy.ErrInvalidName):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeInternal(w, err)
	}
}
