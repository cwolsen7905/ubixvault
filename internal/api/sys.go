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
	"log"
	"net/http"
	"time"

	"github.com/cwolsen7905/ubixvault/internal/approle"
	"github.com/cwolsen7905/ubixvault/internal/audit"
	"github.com/cwolsen7905/ubixvault/internal/certauth"
	"github.com/cwolsen7905/ubixvault/internal/core"
	"github.com/cwolsen7905/ubixvault/internal/database"
	"github.com/cwolsen7905/ubixvault/internal/database/mariadb"
	"github.com/cwolsen7905/ubixvault/internal/jwtauth"
	"github.com/cwolsen7905/ubixvault/internal/kubeauth"
	"github.com/cwolsen7905/ubixvault/internal/kv"
	"github.com/cwolsen7905/ubixvault/internal/metrics"
	"github.com/cwolsen7905/ubixvault/internal/pki"
	"github.com/cwolsen7905/ubixvault/internal/policy"
	"github.com/cwolsen7905/ubixvault/internal/ratelimit"
	"github.com/cwolsen7905/ubixvault/internal/token"
	"github.com/cwolsen7905/ubixvault/internal/transit"
	"github.com/cwolsen7905/ubixvault/internal/userpass"
	"github.com/cwolsen7905/ubixvault/internal/wrapping"
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
	core           *core.Core
	kv             *kv.Engine
	transit        *transit.Engine
	database       *database.Engine
	pki            *pki.Engine
	kubernetes     *kubeauth.Method
	approle        *approle.Method
	userpass       *userpass.Method
	jwtauth        *jwtauth.Method
	certauth       *certauth.Method
	wrapping       *wrapping.Store
	tokens         *token.Store
	policies       *policy.Store
	audit          *audit.Broker
	metrics        *metrics.Metrics
	limiter        *ratelimit.Limiter // nil disables rate limiting
	trustForwarded bool               // key rate limits by X-Forwarded-For
	version        string
	startTime      time.Time
	mux            *http.ServeMux
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

// WithRateLimit throttles API requests through l, keyed by client. Health,
// metrics, and the console are exempt.
func WithRateLimit(l *ratelimit.Limiter) Option {
	return func(h *Handler) { h.limiter = l }
}

// WithTrustForwardedFor keys rate limits by the leftmost X-Forwarded-For entry
// instead of the direct peer. Enable only behind a trusted proxy, since clients
// can otherwise spoof the header to evade limits.
func WithTrustForwardedFor() Option {
	return func(h *Handler) { h.trustForwarded = true }
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
		pki:        pki.New(c.Barrier(), "pki"),
		kubernetes: kubeauth.New(c.Barrier(), c.Tokens(), "auth/kubernetes"),
		approle:    approle.New(c.Barrier(), c.Tokens(), "auth/approle"),
		userpass:   userpass.New(c.Barrier(), c.Tokens(), "auth/userpass"),
		jwtauth:    jwtauth.New(c.Barrier(), c.Tokens(), "auth/jwt"),
		certauth:   certauth.New(c.Barrier(), c.Tokens(), "auth/cert"),
		wrapping:   wrapping.NewStore(c.Barrier()),
		tokens:     c.Tokens(),
		policies:   policy.NewStore(c.Barrier()),
		metrics:    metrics.New(),
		startTime:  time.Now().UTC(),
	}
	mux := http.NewServeMux()

	// Embedded read-only web console at /ui/, with / redirecting to it.
	h.registerUI(mux)

	// System / lifecycle. These are unauthenticated by necessity: there is no
	// token before the vault exists or while it is sealed.
	mux.HandleFunc("GET /v1/sys/health", h.health)
	mux.HandleFunc("GET /v1/sys/livez", h.livez)
	mux.HandleFunc("GET /v1/sys/metrics", h.metricsEndpoint)
	mux.HandleFunc("GET /v1/sys/seal-status", h.sealStatus)
	mux.HandleFunc("POST /v1/sys/init", h.initialize)
	mux.HandleFunc("POST /v1/sys/unseal", h.unseal)
	mux.HandleFunc("POST /v1/sys/seal", h.authenticate(h.seal))

	// Root-token regeneration (recovery). Unauthenticated — authority is proven
	// by supplying a quorum of unseal shares, since the root token is lost.
	mux.HandleFunc("GET /v1/sys/generate-root/attempt", h.generateRootStatus)
	mux.HandleFunc("POST /v1/sys/generate-root/init", h.generateRootInit)
	mux.HandleFunc("DELETE /v1/sys/generate-root/init", h.generateRootCancel)
	mux.HandleFunc("POST /v1/sys/generate-root/update", h.generateRootUpdate)

	// Rekey — rotate the unseal shares by re-splitting the master key. Like
	// generate-root, unauthenticated: authority is a quorum of current shares.
	mux.HandleFunc("GET /v1/sys/rekey/init", h.rekeyStatus)
	mux.HandleFunc("POST /v1/sys/rekey/init", h.rekeyInit)
	mux.HandleFunc("DELETE /v1/sys/rekey/init", h.rekeyCancel)
	mux.HandleFunc("POST /v1/sys/rekey/update", h.rekeyUpdate)

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

	// Token creation, renewal, and revocation (revoke cascades to the token's
	// dynamic-database leases).
	mux.HandleFunc("POST /v1/auth/token/create", h.authenticate(h.tokenCreate))
	mux.HandleFunc("POST /v1/auth/token/renew-self", h.authenticate(h.renewSelf))
	mux.HandleFunc("POST /v1/auth/token/revoke-self", h.authenticate(h.tokenRevokeSelf))

	// Response wrapping: wrap a payload in a single-use, TTL'd token, and unwrap
	// it exactly once. Both require a token; the wrapping token is passed in the
	// unwrap body.
	mux.HandleFunc("POST /v1/sys/wrapping/wrap", h.authenticate(h.sysWrappingWrap))
	mux.HandleFunc("POST /v1/sys/wrapping/unwrap", h.authenticate(h.sysWrappingUnwrap))

	// Transit engine (encryption-as-a-service).
	mux.HandleFunc("POST /v1/transit/keys/{name}", h.authenticate(h.transitCreateKey))
	mux.HandleFunc("GET /v1/transit/keys/{name}", h.authenticate(h.transitReadKey))
	mux.HandleFunc("DELETE /v1/transit/keys/{name}", h.authenticate(h.transitDeleteKey))
	mux.HandleFunc("LIST /v1/transit/keys", h.authenticate(h.transitListKeys))
	mux.HandleFunc("POST /v1/transit/keys/{name}/rotate", h.authenticate(h.transitRotateKey))
	mux.HandleFunc("POST /v1/transit/encrypt/{name}", h.authenticate(h.transitEncrypt))
	mux.HandleFunc("POST /v1/transit/decrypt/{name}", h.authenticate(h.transitDecrypt))
	mux.HandleFunc("POST /v1/transit/rewrap/{name}", h.authenticate(h.transitRewrap))
	mux.HandleFunc("POST /v1/transit/datakey/{mode}/{name}", h.authenticate(h.transitDataKey))
	mux.HandleFunc("POST /v1/transit/hmac/{name}", h.authenticate(h.transitHMAC))
	mux.HandleFunc("POST /v1/transit/sign/{name}", h.authenticate(h.transitSign))
	mux.HandleFunc("POST /v1/transit/verify/{name}", h.authenticate(h.transitVerify))

	// Dynamic database secrets engine.
	mux.HandleFunc("POST /v1/database/config", h.authenticate(h.dbConfigure))
	mux.HandleFunc("GET /v1/database/config", h.authenticate(h.dbConfigStatus))
	mux.HandleFunc("POST /v1/database/roles/{name}", h.authenticate(h.dbWriteRole))
	mux.HandleFunc("PUT /v1/database/roles/{name}", h.authenticate(h.dbWriteRole))
	mux.HandleFunc("GET /v1/database/roles/{name}", h.authenticate(h.dbReadRole))
	mux.HandleFunc("LIST /v1/database/roles", h.authenticate(h.dbListRoles))
	mux.HandleFunc("DELETE /v1/database/roles/{name}", h.authenticate(h.dbDeleteRole))
	mux.HandleFunc("GET /v1/database/creds/{name}", h.authenticate(h.dbCredentials))

	// PKI secrets engine — internal CA and short-lived certificate issuance.
	mux.HandleFunc("POST /v1/pki/root/generate/internal", h.authenticate(h.pkiGenerateRoot))
	mux.HandleFunc("GET /v1/pki/ca", h.authenticate(h.pkiReadCA))
	mux.HandleFunc("POST /v1/pki/roles/{name}", h.authenticate(h.pkiWriteRole))
	mux.HandleFunc("PUT /v1/pki/roles/{name}", h.authenticate(h.pkiWriteRole))
	mux.HandleFunc("GET /v1/pki/roles/{name}", h.authenticate(h.pkiReadRole))
	mux.HandleFunc("LIST /v1/pki/roles", h.authenticate(h.pkiListRoles))
	mux.HandleFunc("DELETE /v1/pki/roles/{name}", h.authenticate(h.pkiDeleteRole))
	mux.HandleFunc("POST /v1/pki/issue/{role}", h.authenticate(h.pkiIssue))

	// Lease management (currently database leases only).
	mux.HandleFunc("PUT /v1/sys/leases/revoke", h.authenticate(h.leaseRevoke))
	mux.HandleFunc("PUT /v1/sys/leases/renew", h.authenticate(h.leaseRenew))
	mux.HandleFunc("PUT /v1/sys/leases/lookup", h.authenticate(h.leaseLookup))

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

	// AppRole auth method. login is unauthenticated (role_id + secret_id are the
	// credential); role and secret-id management require authentication.
	mux.HandleFunc("POST /v1/auth/approle/role/{name}", h.authenticate(h.approleWriteRole))
	mux.HandleFunc("PUT /v1/auth/approle/role/{name}", h.authenticate(h.approleWriteRole))
	mux.HandleFunc("GET /v1/auth/approle/role/{name}", h.authenticate(h.approleReadRole))
	mux.HandleFunc("LIST /v1/auth/approle/role", h.authenticate(h.approleListRoles))
	mux.HandleFunc("DELETE /v1/auth/approle/role/{name}", h.authenticate(h.approleDeleteRole))
	mux.HandleFunc("GET /v1/auth/approle/role/{name}/role-id", h.authenticate(h.approleReadRoleID))
	mux.HandleFunc("POST /v1/auth/approle/role/{name}/secret-id", h.authenticate(h.approleGenerateSecretID))
	mux.HandleFunc("POST /v1/auth/approle/login", h.approleLogin)

	// Userpass auth method. login is unauthenticated (the password is the
	// credential); user management requires authentication.
	mux.HandleFunc("POST /v1/auth/userpass/users/{username}", h.authenticate(h.userpassWriteUser))
	mux.HandleFunc("PUT /v1/auth/userpass/users/{username}", h.authenticate(h.userpassWriteUser))
	mux.HandleFunc("GET /v1/auth/userpass/users/{username}", h.authenticate(h.userpassReadUser))
	mux.HandleFunc("LIST /v1/auth/userpass/users", h.authenticate(h.userpassListUsers))
	mux.HandleFunc("DELETE /v1/auth/userpass/users/{username}", h.authenticate(h.userpassDeleteUser))
	mux.HandleFunc("POST /v1/auth/userpass/login/{username}", h.userpassLogin)

	// JWT/OIDC auth: configure signature validation and roles (authenticated),
	// then exchange a signed JWT for a token (unauthenticated).
	mux.HandleFunc("POST /v1/auth/jwt/config", h.authenticate(h.jwtConfigure))
	mux.HandleFunc("PUT /v1/auth/jwt/config", h.authenticate(h.jwtConfigure))
	mux.HandleFunc("POST /v1/auth/jwt/role/{name}", h.authenticate(h.jwtWriteRole))
	mux.HandleFunc("PUT /v1/auth/jwt/role/{name}", h.authenticate(h.jwtWriteRole))
	mux.HandleFunc("GET /v1/auth/jwt/role/{name}", h.authenticate(h.jwtReadRole))
	mux.HandleFunc("LIST /v1/auth/jwt/role", h.authenticate(h.jwtListRoles))
	mux.HandleFunc("DELETE /v1/auth/jwt/role/{name}", h.authenticate(h.jwtDeleteRole))
	mux.HandleFunc("POST /v1/auth/jwt/login", h.jwtLogin)

	// TLS certificate auth: define trusted cert roles (authenticated), then log in
	// by presenting a matching mTLS client certificate (unauthenticated).
	mux.HandleFunc("POST /v1/auth/cert/certs/{name}", h.authenticate(h.certWriteCert))
	mux.HandleFunc("PUT /v1/auth/cert/certs/{name}", h.authenticate(h.certWriteCert))
	mux.HandleFunc("GET /v1/auth/cert/certs/{name}", h.authenticate(h.certReadCert))
	mux.HandleFunc("LIST /v1/auth/cert/certs", h.authenticate(h.certListCerts))
	mux.HandleFunc("DELETE /v1/auth/cert/certs/{name}", h.authenticate(h.certDeleteCert))
	mux.HandleFunc("POST /v1/auth/cert/login", h.certLogin)

	h.mux = mux
	for _, opt := range opts {
		opt(h)
	}
	// Register metrics after options so gauges like build_info capture the
	// version set by WithVersion.
	h.registerMetrics()
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
	Keys               []string `json:"keys"`                           // hex-encoded unseal shares (Shamir mode)
	KeysBase64         []string `json:"keys_base64"`                    // same shares, base64
	RecoveryKeys       []string `json:"recovery_keys,omitempty"`        // hex-encoded recovery shares (auto-unseal mode)
	RecoveryKeysBase64 []string `json:"recovery_keys_base64,omitempty"` // same recovery shares, base64
	RootToken          string   `json:"root_token"`                     // initial root token, shown once
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
		writeInternal(w, err)
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
	for _, k := range res.RecoveryKeys {
		resp.RecoveryKeys = append(resp.RecoveryKeys, hex.EncodeToString(k))
		resp.RecoveryKeysBase64 = append(resp.RecoveryKeysBase64, base64.StdEncoding.EncodeToString(k))
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

// writeInternal handles an unexpected server-side error: it logs the detail for
// the operator but returns only a generic message to the client, so internal
// error strings (storage paths, wrapped chains) are not disclosed.
func writeInternal(w http.ResponseWriter, err error) {
	log.Printf("api: internal error: %v", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}
