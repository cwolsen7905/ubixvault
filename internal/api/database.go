package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/barrier"
	"github.com/cwolsen7905/ubixvault/internal/database"
)

type dbConfigRequest struct {
	ConnectionURL string `json:"connection_url"`
}

type dbRoleRequest struct {
	CreationStatements []string `json:"creation_statements"`
	DefaultTTL         string   `json:"default_ttl"` // duration string, e.g. "1h"
}

func (h *Handler) dbConfigure(w http.ResponseWriter, r *http.Request) {
	var req dbConfigRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ConnectionURL == "" {
		writeError(w, http.StatusBadRequest, "connection_url is required")
		return
	}
	if err := h.database.Configure(r.Context(), req.ConnectionURL); err != nil {
		// A failed Configure is most likely a bad connection string or an
		// unreachable database — a client error.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) dbConfigStatus(w http.ResponseWriter, r *http.Request) {
	ok, err := h.database.Configured(r.Context())
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeData(w, map[string]any{"configured": ok})
}

func (h *Handler) dbWriteRole(w http.ResponseWriter, r *http.Request) {
	var req dbRoleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ttl, err := time.ParseDuration(req.DefaultTTL)
	if err != nil || ttl <= 0 {
		writeError(w, http.StatusBadRequest, "default_ttl must be a positive duration (e.g. \"1h\")")
		return
	}
	role := database.Role{CreationStatements: req.CreationStatements, DefaultTTL: ttl}
	if err := h.database.WriteRole(r.Context(), r.PathValue("name"), role); err != nil {
		writeDatabaseError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) dbReadRole(w http.ResponseWriter, r *http.Request) {
	role, err := h.database.ReadRole(r.Context(), r.PathValue("name"))
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeData(w, map[string]any{
		"creation_statements": role.CreationStatements,
		"default_ttl":         role.DefaultTTL.String(),
	})
}

func (h *Handler) dbListRoles(w http.ResponseWriter, r *http.Request) {
	names, err := h.database.ListRoles(r.Context())
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeData(w, map[string]any{"keys": names})
}

func (h *Handler) dbDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := h.database.DeleteRole(r.Context(), r.PathValue("name")); err != nil {
		writeDatabaseError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// dbCredentials issues a fresh short-lived database credential for a role.
func (h *Handler) dbCredentials(w http.ResponseWriter, r *http.Request) {
	cred, err := h.database.GenerateCredentials(r.Context(), r.PathValue("name"))
	if err != nil {
		writeDatabaseError(w, err)
		return
	}
	writeData(w, map[string]any{
		"lease_id":       cred.LeaseID,
		"lease_duration": int(cred.TTL.Seconds()),
		"username":       cred.Username,
		"password":       cred.Password,
	})
}

type leaseRevokeRequest struct {
	LeaseID string `json:"lease_id"`
}

func (h *Handler) leaseRevoke(w http.ResponseWriter, r *http.Request) {
	var req leaseRevokeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := h.database.Revoke(r.Context(), req.LeaseID); err != nil {
		writeDatabaseError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeDatabaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, barrier.ErrSealed):
		writeError(w, http.StatusServiceUnavailable, "vault is sealed")
	case errors.Is(err, database.ErrRoleNotFound), errors.Is(err, database.ErrLeaseNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, database.ErrNotConfigured), errors.Is(err, database.ErrInvalidName):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
