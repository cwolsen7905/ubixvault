package api

import (
	"net/http"
	"time"
)

type healthResponse struct {
	Initialized   bool   `json:"initialized"`
	Sealed        bool   `json:"sealed"`
	Version       string `json:"version,omitempty"`
	ServerTimeUTC int64  `json:"server_time_utc"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// health reports readiness. The HTTP status encodes it so load balancers and
// probes can act without parsing the body:
//   - 200 initialized and unsealed (ready)
//   - 503 sealed (not ready)
//   - 501 not initialized
//
// For process liveness (which must ignore seal state) use livez instead. This
// endpoint is unauthenticated and excluded from audit logging (see ServeHTTP).
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	st, err := h.core.Status(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}

	code := http.StatusOK
	switch {
	case !st.Initialized:
		code = http.StatusNotImplemented // 501
	case st.Sealed:
		code = http.StatusServiceUnavailable // 503
	}

	now := time.Now().UTC()
	writeJSON(w, code, healthResponse{
		Initialized:   st.Initialized,
		Sealed:        st.Sealed,
		Version:       h.version,
		ServerTimeUTC: now.Unix(),
		UptimeSeconds: int64(now.Sub(h.startTime).Seconds()),
	})
}

// livez reports process liveness. Unlike health (whose status encodes
// readiness — 501 uninitialized, 503 sealed), livez returns 200 whenever the
// HTTP server is serving, regardless of init/seal state. That makes it safe as
// a Kubernetes liveness probe: it never fails during the normal sealed window,
// so it will not crash-loop a sealed vault, while still confirming the HTTP
// server actually responds (which a bare TCP probe cannot). Unauthenticated and
// audit-exempt, like health.
func (h *Handler) livez(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"alive": true})
}
