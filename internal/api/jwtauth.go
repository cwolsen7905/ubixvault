package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/jwtauth"
	"github.com/cwolsen7905/ubixvault/internal/token"
)

type jwtConfigRequest struct {
	JWKSURL           string   `json:"jwks_url"`
	OIDCDiscoveryURL  string   `json:"oidc_discovery_url"`
	ValidationPubKeys []string `json:"jwt_validation_pubkeys"`
	BoundIssuer       string   `json:"bound_issuer"`
	GroupsClaim       string   `json:"groups_claim"`
}

// jwtRoleRequest is a role write. Every field is optional: as in Vault, a
// write to an existing role changes only the fields it sends.
type jwtRoleRequest struct {
	BoundAudiences *stringList        `json:"bound_audiences"`
	BoundClaims    *map[string]string `json:"bound_claims"`
	Policies       *stringList        `json:"policies"`
	TokenPolicies  *stringList        `json:"token_policies"` // Vault's current name; wins over policies
	TokenTTL       *vaultDuration     `json:"token_ttl"`
	TokenMaxTTL    *vaultDuration     `json:"token_max_ttl"`
}

type jwtLoginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

func (h *Handler) jwtConfigure(w http.ResponseWriter, r *http.Request) {
	var req jwtConfigRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	err := h.jwtauth.Configure(r.Context(), jwtauth.Config{
		JWKSURL:           req.JWKSURL,
		OIDCDiscoveryURL:  req.OIDCDiscoveryURL,
		ValidationPubKeys: req.ValidationPubKeys,
		BoundIssuer:       req.BoundIssuer,
		GroupsClaim:       req.GroupsClaim,
	})
	if err != nil {
		writeJWTError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// errTTLOverMax refuses a role whose token_ttl would exceed its token_max_ttl.
var errTTLOverMax = errors.New("token_ttl must not exceed token_max_ttl")

func (h *Handler) jwtWriteRole(w http.ResponseWriter, r *http.Request) {
	var req jwtRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Parse the durations before taking the role lock.
	var ttl, maxTTL *time.Duration
	if req.TokenTTL != nil {
		d, ok := parseOptionalDuration(w, string(*req.TokenTTL), "token_ttl")
		if !ok {
			return
		}
		ttl = &d
	}
	if req.TokenMaxTTL != nil {
		d, ok := parseOptionalDuration(w, string(*req.TokenMaxTTL), "token_max_ttl")
		if !ok {
			return
		}
		maxTTL = &d
	}

	err := h.jwtauth.UpdateRole(r.Context(), r.PathValue("name"), func(role *jwtauth.Role) error {
		if req.BoundAudiences != nil {
			role.BoundAudiences = *req.BoundAudiences
		}
		if req.BoundClaims != nil {
			role.BoundClaims = *req.BoundClaims
		}
		switch {
		case req.TokenPolicies != nil:
			role.Policies = *req.TokenPolicies
		case req.Policies != nil:
			role.Policies = *req.Policies
		}
		if ttl != nil {
			role.TokenTTL = *ttl
		}
		if maxTTL != nil {
			role.TokenMaxTTL = *maxTTL
		}
		if role.TokenMaxTTL > 0 && role.TokenTTL > role.TokenMaxTTL {
			return errTTLOverMax
		}
		return nil
	})
	if errors.Is(err, errTTLOverMax) {
		writeError(w, http.StatusBadRequest, errTTLOverMax.Error())
		return
	}
	if err != nil {
		writeJWTError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) jwtReadRole(w http.ResponseWriter, r *http.Request) {
	role, err := h.jwtauth.ReadRole(r.Context(), r.PathValue("name"))
	if err != nil {
		writeJWTError(w, err)
		return
	}
	writeData(w, map[string]any{
		"bound_audiences": role.BoundAudiences,
		"bound_claims":    role.BoundClaims,
		"policies":        role.Policies,
		"token_policies":  role.Policies,
		"token_ttl":       role.TokenTTL.String(),
		"token_max_ttl":   role.TokenMaxTTL.String(),
	})
}

func (h *Handler) jwtListRoles(w http.ResponseWriter, r *http.Request) {
	names, err := h.jwtauth.ListRoles(r.Context())
	if err != nil {
		writeJWTError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

func (h *Handler) jwtDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := h.jwtauth.DeleteRole(r.Context(), r.PathValue("name")); err != nil {
		writeJWTError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// jwtLogin is unauthenticated: the signed JWT is the credential.
func (h *Handler) jwtLogin(w http.ResponseWriter, r *http.Request) {
	var req jwtLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tok, err := h.jwtauth.Login(r.Context(), req.Role, req.JWT)
	if err != nil {
		writeJWTError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenAuthResponse(tok))
}

func writeJWTError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, jwtauth.ErrDenied):
		writeError(w, http.StatusForbidden, "permission denied")
	case errors.Is(err, jwtauth.ErrNotConfigured):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, jwtauth.ErrRoleNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, token.ErrRootPolicy):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, jwtauth.ErrInvalidName), errors.Is(err, jwtauth.ErrInvalidConfig):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeInternal(w, err)
	}
}
