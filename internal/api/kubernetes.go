package api

import (
	"errors"
	"net/http"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/kubeauth"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

type k8sConfigRequest struct {
	Host        string `json:"kubernetes_host"`
	CACert      string `json:"kubernetes_ca_cert"`
	ReviewerJWT string `json:"token_reviewer_jwt"`
}

// k8sRoleRequest is a role write; every field is optional (see partial.go).
// token_policies and token_ttl are Vault's current names and win over the
// older policies and ttl.
type k8sRoleRequest struct {
	BoundServiceAccountNames      *stringList    `json:"bound_service_account_names"`
	BoundServiceAccountNamespaces *stringList    `json:"bound_service_account_namespaces"`
	Policies                      *stringList    `json:"policies"`
	TokenPolicies                 *stringList    `json:"token_policies"`
	TTL                           *vaultDuration `json:"ttl"`
	TokenTTL                      *vaultDuration `json:"token_ttl"`
	TokenMaxTTL                   *vaultDuration `json:"token_max_ttl"`
}

type k8sLoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

func (h *Handler) k8sConfigure(w http.ResponseWriter, r *http.Request) {
	var req k8sConfigRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Host == "" {
		writeError(w, http.StatusBadRequest, "kubernetes_host is required")
		return
	}
	cfg := kubeauth.Config{Host: req.Host, CACert: req.CACert, ReviewerJWT: req.ReviewerJWT}
	if err := h.kubernetes.Configure(r.Context(), cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) k8sWriteRole(w http.ResponseWriter, r *http.Request) {
	var req k8sRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ttl, ok := optionalDuration(w, firstSet(req.TokenTTL, req.TTL), "token_ttl")
	if !ok {
		return
	}
	maxTTL, ok := optionalDuration(w, req.TokenMaxTTL, "token_max_ttl")
	if !ok {
		return
	}
	err := h.kubernetes.UpdateRole(r.Context(), r.PathValue("name"), func(role *kubeauth.Role) error {
		applyList(&role.BoundServiceAccountNames, req.BoundServiceAccountNames)
		applyList(&role.BoundServiceAccountNamespaces, req.BoundServiceAccountNamespaces)
		applyList(&role.Policies, firstSet(req.TokenPolicies, req.Policies))
		apply(&role.TTL, ttl)
		apply(&role.TokenMaxTTL, maxTTL)
		return checkTTL(role.TTL, role.TokenMaxTTL)
	})
	if err != nil {
		writeRoleUpdateError(w, err, writeKubeError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) k8sReadRole(w http.ResponseWriter, r *http.Request) {
	role, err := h.kubernetes.ReadRole(r.Context(), r.PathValue("name"))
	if err != nil {
		writeKubeError(w, err)
		return
	}
	writeData(w, map[string]any{
		"bound_service_account_names":      role.BoundServiceAccountNames,
		"bound_service_account_namespaces": role.BoundServiceAccountNamespaces,
		"policies":                         role.Policies,
		"token_policies":                   role.Policies,
		"ttl":                              role.TTL.String(),
		"token_ttl":                        role.TTL.String(),
		"token_max_ttl":                    role.TokenMaxTTL.String(),
	})
}

func (h *Handler) k8sListRoles(w http.ResponseWriter, r *http.Request) {
	names, err := h.kubernetes.ListRoles(r.Context())
	if err != nil {
		writeKubeError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

func (h *Handler) k8sDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := h.kubernetes.DeleteRole(r.Context(), r.PathValue("name")); err != nil {
		writeKubeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// k8sLogin is unauthenticated: the ServiceAccount JWT is the credential.
func (h *Handler) k8sLogin(w http.ResponseWriter, r *http.Request) {
	var req k8sLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" || req.JWT == "" {
		writeError(w, http.StatusBadRequest, "role and jwt are required")
		return
	}
	tok, err := h.kubernetes.Login(r.Context(), req.Role, req.JWT)
	if err != nil {
		writeKubeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{
			"client_token": tok.ID,
			"policies":     tok.Policies,
		},
	})
}

func writeKubeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, kubeauth.ErrDenied):
		writeError(w, http.StatusForbidden, "permission denied")
	case errors.Is(err, kubeauth.ErrRoleNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, kubeauth.ErrNotConfigured), errors.Is(err, kubeauth.ErrInvalidName),
		errors.Is(err, token.ErrRootPolicy):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeInternal(w, err)
	}
}
