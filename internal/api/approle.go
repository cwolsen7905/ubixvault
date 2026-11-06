package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/approle"
	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// approleRoleRequest is a role write; every field is optional (see partial.go).
type approleRoleRequest struct {
	Policies      *stringList    `json:"policies"`
	TokenPolicies *stringList    `json:"token_policies"` // Vault's current name; wins over policies
	TokenTTL      *vaultDuration `json:"token_ttl"`
	TokenMaxTTL   *vaultDuration `json:"token_max_ttl"`
	SecretIDTTL   *vaultDuration `json:"secret_id_ttl"`
}

type approleLoginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

func (h *Handler) approleWriteRole(w http.ResponseWriter, r *http.Request) {
	var req approleRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tokenTTL, ok := optionalDuration(w, req.TokenTTL, "token_ttl")
	if !ok {
		return
	}
	secretTTL, ok := optionalDuration(w, req.SecretIDTTL, "secret_id_ttl")
	if !ok {
		return
	}
	maxTTL, ok := optionalDuration(w, req.TokenMaxTTL, "token_max_ttl")
	if !ok {
		return
	}
	err := h.approle.UpdateRole(r.Context(), r.PathValue("name"), func(role *approle.Role) error {
		applyList(&role.Policies, firstSet(req.TokenPolicies, req.Policies))
		apply(&role.TokenTTL, tokenTTL)
		apply(&role.TokenMaxTTL, maxTTL)
		apply(&role.SecretIDTTL, secretTTL)
		return checkTTL(role.TokenTTL, role.TokenMaxTTL)
	})
	if err != nil {
		writeRoleUpdateError(w, err, writeAppRoleError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) approleReadRole(w http.ResponseWriter, r *http.Request) {
	role, err := h.approle.ReadRole(r.Context(), r.PathValue("name"))
	if err != nil {
		writeAppRoleError(w, err)
		return
	}
	writeData(w, map[string]any{
		"policies":       role.Policies,
		"token_policies": role.Policies,
		"token_ttl":      role.TokenTTL.String(),
		"token_max_ttl":  role.TokenMaxTTL.String(),
		"secret_id_ttl":  role.SecretIDTTL.String(),
	})
}

func (h *Handler) approleListRoles(w http.ResponseWriter, r *http.Request) {
	names, err := h.approle.ListRoles(r.Context())
	if err != nil {
		writeAppRoleError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

func (h *Handler) approleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := h.approle.DeleteRole(r.Context(), r.PathValue("name")); err != nil {
		writeAppRoleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) approleReadRoleID(w http.ResponseWriter, r *http.Request) {
	roleID, err := h.approle.RoleID(r.Context(), r.PathValue("name"))
	if err != nil {
		writeAppRoleError(w, err)
		return
	}
	writeData(w, map[string]any{"role_id": roleID})
}

func (h *Handler) approleGenerateSecretID(w http.ResponseWriter, r *http.Request) {
	secretID, err := h.approle.GenerateSecretID(r.Context(), r.PathValue("name"))
	if err != nil {
		writeAppRoleError(w, err)
		return
	}
	writeData(w, map[string]any{"secret_id": secretID})
}

// approleLogin is unauthenticated: the role_id + secret_id pair is the credential.
func (h *Handler) approleLogin(w http.ResponseWriter, r *http.Request) {
	var req approleLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tok, err := h.approle.Login(r.Context(), req.RoleID, req.SecretID)
	if err != nil {
		writeAppRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenAuthResponse(tok))
}

// parseOptionalDuration parses an optional duration string, writing a 400 and
// returning ok=false on a malformed value. An empty string is a zero duration.
func parseOptionalDuration(w http.ResponseWriter, s, field string) (time.Duration, bool) {
	if s == "" {
		return 0, true
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		writeError(w, http.StatusBadRequest, field+" must be a non-negative duration (e.g. \"1h\")")
		return 0, false
	}
	return d, true
}

func writeAppRoleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, approle.ErrDenied):
		writeError(w, http.StatusForbidden, "permission denied")
	case errors.Is(err, approle.ErrRoleNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, token.ErrRootPolicy):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, approle.ErrInvalidName), errors.Is(err, approle.ErrInvalidConfig):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeInternal(w, err)
	}
}
