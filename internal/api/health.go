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

// health reports liveness/readiness. The HTTP status encodes readiness so load
// balancers and probes can act on it without parsing the body:
//   - 200 initialized and unsealed (ready)
//   - 503 sealed (not ready)
//   - 501 not initialized
//
// It is unauthenticated and excluded from audit logging (see ServeHTTP).
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	st, err := h.core.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
