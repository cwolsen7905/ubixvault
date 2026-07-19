package api

import (
	"net/http"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/audit"
)

// ServeHTTP dispatches to the configured routes. When audit logging is enabled it
// records a request entry before handling and a response entry after. Request
// auditing is fail-closed: if the entry cannot be recorded, the request is
// refused (500) and never processed, so nothing proceeds unaudited.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.audit == nil {
		h.mux.ServeHTTP(w, r)
		return
	}

	base := audit.Entry{
		Operation:   operationForMethod(r.Method),
		Path:        apiPath(r),
		ClientToken: r.Header.Get(tokenHeader),
		RemoteAddr:  r.RemoteAddr,
	}

	req := base
	if err := h.audit.LogRequest(r.Context(), &req); err != nil {
		writeError(w, http.StatusInternalServerError, "audit logging failed")
		return
	}

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.mux.ServeHTTP(rec, r)

	resp := base
	resp.StatusCode = rec.status
	// The request has already been served; a response-audit failure cannot unwind
	// it, so it is best-effort (the fail-closed guarantee is on the request).
	_ = h.audit.LogResponse(r.Context(), &resp)
}

// operationForMethod maps an HTTP method to an audit operation name.
func operationForMethod(method string) string {
	switch method {
	case http.MethodGet:
		return "read"
	case "LIST":
		return "list"
	case http.MethodDelete:
		return "delete"
	case http.MethodPost, http.MethodPut:
		return "update"
	default:
		return strings.ToLower(method)
	}
}

// statusRecorder captures the response status code for auditing.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}
