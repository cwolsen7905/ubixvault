package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/cwolsen7905/ubixvault/internal/audit"
)

// ServeHTTP dispatches to the configured routes. When audit logging is enabled it
// records a request entry before handling and a response entry after. Request
// auditing is fail-closed: if the entry cannot be recorded, the request is
// refused (500) and never processed, so nothing proceeds unaudited.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Wrap once so both metrics and audit see the final status code; count every
	// request toward metrics regardless of the decisions below.
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() { h.metrics.ObserveRequest(rec.status) }()

	// Rate limiting: throttle authenticated/lifecycle endpoints (health, metrics,
	// and the console are exempt so probes/scrapers/browsers aren't blocked).
	if h.limiter != nil && !publicEndpoint(r.URL.Path) {
		if !h.limiter.Allow(h.clientKey(r)) {
			rec.Header().Set("Retry-After", "1")
			writeError(rec, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
	}

	// Public endpoints (health, metrics, console) are not audited.
	if h.audit == nil || publicEndpoint(r.URL.Path) {
		h.mux.ServeHTTP(rec, r)
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
		writeError(rec, http.StatusInternalServerError, "audit logging failed")
		return
	}

	h.mux.ServeHTTP(rec, r)

	resp := base
	resp.StatusCode = rec.status
	// The request has already been served; a response-audit failure cannot unwind
	// it, so it is best-effort (the fail-closed guarantee is on the request).
	_ = h.audit.LogResponse(r.Context(), &resp)
}

// publicEndpoint reports whether a path is an unauthenticated, non-sensitive
// endpoint — the health/metrics endpoints and the static console assets. These
// are exempt from both auditing and rate limiting. (The /v1/* calls the console
// makes on the operator's behalf are audited and rate-limited normally.)
func publicEndpoint(path string) bool {
	if strings.HasPrefix(path, "/ui/") {
		return true
	}
	switch path {
	case "/", "/ui", "/v1/sys/health", "/v1/sys/livez", "/v1/sys/metrics":
		return true
	default:
		return false
	}
}

// clientKey identifies the caller for rate limiting: the direct peer IP, or the
// leftmost X-Forwarded-For entry when trustForwarded is set (behind a proxy).
func (h *Handler) clientKey(r *http.Request) string {
	if h.trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
