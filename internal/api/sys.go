// Package api exposes uBix Vault's HTTP interface. This first cut implements the
// system endpoints for initialization and the seal/unseal lifecycle
// (docs/DESIGN.md §4). Paths mirror HashiCorp Vault's for client compatibility.
package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/audit"
	"github.com/cwolsen7905/ubixvault/internal/core"
	"github.com/cwolsen7905/ubixvault/internal/database"
	"github.com/cwolsen7905/ubixvault/internal/database/mariadb"
	"github.com/cwolsen7905/ubixvault/internal/kubeauth"
	"github.com/cwolsen7905/ubixvault/internal/kv"
	"github.com/cwolsen7905/ubixvault/internal/policy"
	"github.com/cwolsen7905/ubixvault/internal/token"
	"github.com/cwolsen7905/ubixvault/internal/transit"
)

// maxBodyBytes caps request bodies to guard against oversized payloads.
const maxBodyBytes = 1 << 20 // 1 MiB

// Storage prefixes under which the engines are mounted.
const (
	kvMountPrefix       = "secret"
	transitMountPrefix  = "transit"
	databaseMountPrefix = "database"
)

// Handler serves the HTTP API over a Core and its mounted engines. It implements
// [http.Handler].
type Handler struct {
	core       *core.Core
	kv         *kv.Engine
	transit    *transit.Engine
	database   *database.Engine
	kubernetes *kubeauth.Method
	tokens     *token.Store
	policies   *policy.Store
	audit      *audit.Broker
	version    string
	startTime  time.Time
	mux        *http.ServeMux
}

// Option configures a Handler.
type Option func(*Handler)

// WithAudit enables audit logging through the given broker.
func WithAudit(b *audit.Broker) Option {
	return func(h *Handler) { h.audit = b }
}

// WithVersion sets the build version reported by the health endpoint.
func WithVersion(v string) Option {
	return func(h *Handler) { h.version = v }
}

// NewHandler returns a Handler backed by c, with the KV v2, transit, and dynamic
// database engines mounted on the core's barrier. The database engine uses the
// MariaDB reference plugin.
func NewHandler(c *core.Core, opts ...Option) *Handler {
	h := &Handler{
		core:       c,
		kv:         kv.New(c.Barrier(), kvMountPrefix),
		transit:    transit.New(c.Barrier(), transitMountPrefix),
		database:   database.New(c.Barrier(), databaseMountPrefix, mariadb.New()),
		kubernetes: kubeauth.New(c.Barrier(), c.Tokens(), "auth/kubernetes"),
		tokens:     c.Tokens(),
		policies:   policy.NewStore(c.Barrier()),
		startTime:  time.Now().UTC(),
	}
	mux := http.NewServeMux()

	// System / lifecycle. These are unauthenticated by necessity: there is no
	// token before the vault exists or while it is sealed.
	mux.HandleFunc("GET /v1/sys/health", h.health)
	mux.HandleFunc("GET /v1/sys/seal-status", h.sealStatus)
	mux.HandleFunc("POST /v1/sys/init", h.initialize)
	mux.HandleFunc("POST /v1/sys/unseal", h.unseal)
	mux.HandleFunc("POST /v1/sys/seal", h.authenticate(h.seal))

	// KV v2 secrets engine — all endpoints require authentication.
	mux.HandleFunc("GET /v1/secret/data/{path...}", h.authenticate(h.kvRead))
	mux.HandleFunc("POST /v1/secret/data/{path...}", h.authenticate(h.kvWrite))
	mux.HandleFunc("DELETE /v1/secret/data/{path...}", h.authenticate(h.kvDeleteLatest))
	mux.HandleFunc("POST /v1/secret/delete/{path...}", h.authenticate(h.kvDeleteVersions))
	mux.HandleFunc("POST /v1/secret/undelete/{path...}", h.authenticate(h.kvUndelete))
	mux.HandleFunc("POST /v1/secret/destroy/{path...}", h.authenticate(h.kvDestroy))
	mux.HandleFunc("GET /v1/secret/metadata/{path...}", h.authenticate(h.kvReadMetadata))
	mux.HandleFunc("LIST /v1/secret/metadata/{path...}", h.authenticate(h.kvList))
	mux.HandleFunc("DELETE /v1/secret/metadata/{path...}", h.authenticate(h.kvDeleteMetadata))

	// ACL policies (governed by the same ACL check; root or an explicit grant).
	mux.HandleFunc("PUT /v1/sys/policies/acl/{name}", h.authenticate(h.policyWrite))
	mux.HandleFunc("POST /v1/sys/policies/acl/{name}", h.authenticate(h.policyWrite))
	mux.HandleFunc("GET /v1/sys/policies/acl/{name}", h.authenticate(h.policyRead))
	mux.HandleFunc("DELETE /v1/sys/policies/acl/{name}", h.authenticate(h.policyDelete))
	mux.HandleFunc("LIST /v1/sys/policies/acl", h.authenticate(h.policyList))

	// Token creation and renewal.
	mux.HandleFunc("POST /v1/auth/token/create", h.authenticate(h.tokenCreate))
	mux.HandleFunc("POST /v1/auth/token/renew-self", h.authenticate(h.renewSelf))

	// Transit engine (encryption-as-a-service).
	mux.HandleFunc("POST /v1/transit/keys/{name}", h.authenticate(h.transitCreateKey))
	mux.HandleFunc("GET /v1/transit/keys/{name}", h.authenticate(h.transitReadKey))
	mux.HandleFunc("DELETE /v1/transit/keys/{name}", h.authenticate(h.transitDeleteKey))
	mux.HandleFunc("LIST /v1/transit/keys", h.authenticate(h.transitListKeys))
	mux.HandleFunc("POST /v1/transit/keys/{name}/rotate", h.authenticate(h.transitRotateKey))
	mux.HandleFunc("POST /v1/transit/encrypt/{name}", h.authenticate(h.transitEncrypt))
	mux.HandleFunc("POST /v1/transit/decrypt/{name}", h.authenticate(h.transitDecrypt))

	// Dynamic database secrets engine.
	mux.HandleFunc("POST /v1/database/config", h.authenticate(h.dbConfigure))
	mux.HandleFunc("GET /v1/database/config", h.authenticate(h.dbConfigStatus))
	mux.HandleFunc("POST /v1/database/roles/{name}", h.authenticate(h.dbWriteRole))
	mux.HandleFunc("PUT /v1/database/roles/{name}", h.authenticate(h.dbWriteRole))
	mux.HandleFunc("GET /v1/database/roles/{name}", h.authenticate(h.dbReadRole))
	mux.HandleFunc("LIST /v1/database/roles", h.authenticate(h.dbListRoles))
	mux.HandleFunc("DELETE /v1/database/roles/{name}", h.authenticate(h.dbDeleteRole))
	mux.HandleFunc("GET /v1/database/creds/{name}", h.authenticate(h.dbCredentials))

	// Lease revocation (currently database leases only).
	mux.HandleFunc("PUT /v1/sys/leases/revoke", h.authenticate(h.leaseRevoke))

	// Backup: stream a snapshot of the encrypted store (root or an explicit grant).
	mux.HandleFunc("POST /v1/sys/snapshot", h.authenticate(h.snapshot))

	// Kubernetes auth method. login is unauthenticated (the ServiceAccount token
	// IS the credential); config and role management require authentication.
	mux.HandleFunc("POST /v1/auth/kubernetes/config", h.authenticate(h.k8sConfigure))
	mux.HandleFunc("POST /v1/auth/kubernetes/role/{name}", h.authenticate(h.k8sWriteRole))
	mux.HandleFunc("GET /v1/auth/kubernetes/role/{name}", h.authenticate(h.k8sReadRole))
	mux.HandleFunc("LIST /v1/auth/kubernetes/role", h.authenticate(h.k8sListRoles))
	mux.HandleFunc("DELETE /v1/auth/kubernetes/role/{name}", h.authenticate(h.k8sDeleteRole))
	mux.HandleFunc("POST /v1/auth/kubernetes/login", h.k8sLogin)

	h.mux = mux
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RunLeaseSweeper periodically revokes expired database leases until ctx is
// cancelled. Errors (including "sealed") are ignored; the next tick retries.
func (h *Handler) RunLeaseSweeper(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = h.database.RevokeExpired(ctx)
		}
	}
}

type initRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type initResponse struct {
	Keys       []string `json:"keys"`        // hex-encoded unseal shares
	KeysBase64 []string `json:"keys_base64"` // same shares, base64
	RootToken  string   `json:"root_token"`  // initial root token, shown once
}

type unsealRequest struct {
	Key string `json:"key"` // a single unseal share, hex or base64
}

type statusResponse struct {
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Type        string `json:"type,omitempty"` // "shamir" or "auto"
	T           int    `json:"t"`              // threshold
	N           int    `json:"n"`              // total shares
	Progress    int    `json:"progress"`
}

type errorResponse struct {
	Errors []string `json:"errors"`
}

func (h *Handler) sealStatus(w http.ResponseWriter, r *http.Request) {
	st, err := h.core.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeStatus(w, st)
}

func (h *Handler) initialize(w http.ResponseWriter, r *http.Request) {
	var req initRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	res, err := h.core.Initialize(r.Context(), core.InitConfig{
		SecretShares:    req.SecretShares,
		SecretThreshold: req.SecretThreshold,
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, core.ErrAlreadyInitialized) {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}

	resp := initResponse{
		Keys:       make([]string, len(res.Keys)),
		KeysBase64: make([]string, len(res.Keys)),
		RootToken:  res.RootToken,
	}
	for i, k := range res.Keys {
		resp.Keys[i] = hex.EncodeToString(k)
		resp.KeysBase64[i] = base64.StdEncoding.EncodeToString(k)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) unseal(w http.ResponseWriter, r *http.Request) {
	var req unsealRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	share, err := decodeShare(req.Key)
	if err != nil {
		writeError(w, http.StatusBadRequest, "key must be valid hex or base64")
		return
	}

	st, err := h.core.Unseal(r.Context(), share)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeStatus(w, st)
}

func (h *Handler) seal(w http.ResponseWriter, _ *http.Request) {
	// NOTE: sealing is unauthenticated until the token/ACL layer lands; it must
	// require sudo before this is exposed beyond a trusted network.
	h.core.Seal()
	w.WriteHeader(http.StatusNoContent)
}

// decodeShare accepts a share encoded as hex or standard base64.
func decodeShare(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// decodeJSON reads a JSON body into v, writing a 400 on failure. It returns
// false if the caller should stop.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

func writeStatus(w http.ResponseWriter, st *core.SealStatus) {
	writeJSON(w, http.StatusOK, statusResponse{
		Initialized: st.Initialized,
		Sealed:      st.Sealed,
		Type:        st.Type,
		T:           st.Threshold,
		N:           st.Shares,
		Progress:    st.Progress,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msgs ...string) {
	writeJSON(w, status, errorResponse{Errors: msgs})
}
