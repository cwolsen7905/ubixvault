package api

import (
	"errors"
	"net/http"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/certauth"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

// certRoleRequest is a cert role write; every field is optional (see
// partial.go).
type certRoleRequest struct {
	Certificate        *string        `json:"certificate"`
	Policies           *stringList    `json:"policies"`
	TokenPolicies      *stringList    `json:"token_policies"` // Vault's current name; wins over policies
	AllowedCommonNames *stringList    `json:"allowed_common_names"`
	TokenTTL           *vaultDuration `json:"token_ttl"`
	TokenMaxTTL        *vaultDuration `json:"token_max_ttl"`
}

func (h *Handler) certWriteCert(w http.ResponseWriter, r *http.Request) {
	var req certRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ttl, ok := optionalDuration(w, req.TokenTTL, "token_ttl")
	if !ok {
		return
	}
	maxTTL, ok := optionalDuration(w, req.TokenMaxTTL, "token_max_ttl")
	if !ok {
		return
	}
	err := h.certauth.UpdateCert(r.Context(), r.PathValue("name"), func(role *certauth.CertRole) error {
		apply(&role.Certificate, req.Certificate)
		applyList(&role.Policies, firstSet(req.TokenPolicies, req.Policies))
		applyList(&role.AllowedCommonNames, req.AllowedCommonNames)
		apply(&role.TokenTTL, ttl)
		apply(&role.TokenMaxTTL, maxTTL)
		return checkTTL(role.TokenTTL, role.TokenMaxTTL)
	})
	if err != nil {
		writeRoleUpdateError(w, err, writeCertError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) certReadCert(w http.ResponseWriter, r *http.Request) {
	role, err := h.certauth.ReadCert(r.Context(), r.PathValue("name"))
	if err != nil {
		writeCertError(w, err)
		return
	}
	writeData(w, map[string]any{
		"certificate":          role.Certificate,
		"policies":             role.Policies,
		"token_policies":       role.Policies,
		"allowed_common_names": role.AllowedCommonNames,
		"token_ttl":            role.TokenTTL.String(),
		"token_max_ttl":        role.TokenMaxTTL.String(),
	})
}

func (h *Handler) certListCerts(w http.ResponseWriter, r *http.Request) {
	names, err := h.certauth.ListCerts(r.Context())
	if err != nil {
		writeCertError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

func (h *Handler) certDeleteCert(w http.ResponseWriter, r *http.Request) {
	if err := h.certauth.DeleteCert(r.Context(), r.PathValue("name")); err != nil {
		writeCertError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// certLogin is unauthenticated: the mTLS client certificate is the credential.
func (h *Handler) certLogin(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeError(w, http.StatusBadRequest, "no client certificate presented")
		return
	}
	tok, err := h.certauth.Login(r.Context(), r.TLS.PeerCertificates)
	if err != nil {
		writeCertError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenAuthResponse(tok))
}

func writeCertError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, certauth.ErrDenied):
		writeError(w, http.StatusForbidden, "permission denied")
	case errors.Is(err, certauth.ErrCertNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, token.ErrRootPolicy):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, certauth.ErrInvalidName), errors.Is(err, certauth.ErrInvalidConfig):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeInternal(w, err)
	}
}
