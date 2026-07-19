// Package api exposes uBix Vault's HTTP interface. This first cut implements the
// system endpoints for initialization and the seal/unseal lifecycle
// (docs/DESIGN.md §4). Paths mirror HashiCorp Vault's for client compatibility.
package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cwolsen7905/ubixvault/internal/core"
)

// maxBodyBytes caps request bodies to guard against oversized payloads.
const maxBodyBytes = 1 << 20 // 1 MiB

// Handler serves the HTTP API over a Core.
type Handler struct {
	core *core.Core
}

// NewHandler returns an http.Handler for the system endpoints backed by c.
func NewHandler(c *core.Core) http.Handler {
	h := &Handler{core: c}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sys/seal-status", h.sealStatus)
	mux.HandleFunc("POST /v1/sys/init", h.initialize)
	mux.HandleFunc("POST /v1/sys/unseal", h.unseal)
	mux.HandleFunc("POST /v1/sys/seal", h.seal)
	return mux
}

type initRequest struct {
	SecretShares    int `json:"secret_shares"`
	SecretThreshold int `json:"secret_threshold"`
}

type initResponse struct {
	Keys       []string `json:"keys"`        // hex-encoded unseal shares
	KeysBase64 []string `json:"keys_base64"` // same shares, base64
}

type unsealRequest struct {
	Key string `json:"key"` // a single unseal share, hex or base64
}

type statusResponse struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	T           int  `json:"t"` // threshold
	N           int  `json:"n"` // total shares
	Progress    int  `json:"progress"`
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
