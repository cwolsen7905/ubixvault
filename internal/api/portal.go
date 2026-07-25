package api

import "net/http"

// portalComingSoon serves an unauthenticated placeholder page at exactly "/",
// standing in for the future admin portal instead of returning a bare 404. It
// deliberately exposes nothing sensitive — no version, seal state, or data — so
// it is safe to serve unauthenticated.
func (h *Handler) portalComingSoon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The page is entirely self-contained, so a tight CSP applies cleanly.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(comingSoonPage))
}

// comingSoonPage is a self-contained (no external assets) placeholder for the
// admin portal, styled to sit comfortably in the uBix family look.
const comingSoonPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>uBix Vault — Admin Portal</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #161616; color: #f4f4f4;
    display: flex; align-items: center; justify-content: center;
    padding: 2rem; line-height: 1.5;
  }
  .card {
    max-width: 34rem; width: 100%;
    border: 1px solid #393939; border-top: 2px solid #4589ff;
    padding: 2.5rem;
  }
  .brand {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: .8rem; letter-spacing: .12em; text-transform: uppercase;
    color: #a8a8a8; margin: 0 0 1.25rem;
  }
  .brand b { color: #f4f4f4; font-weight: 600; }
  h1 { font-size: 2rem; font-weight: 600; margin: 0 0 .75rem; letter-spacing: -.01em; }
  .pill {
    display: inline-block; font-size: .75rem; letter-spacing: .04em;
    color: #4589ff; border: 1px solid #4589ff; border-radius: 999px;
    padding: .15rem .7rem; margin-bottom: 1.25rem;
  }
  p { margin: 0 0 1rem; color: #c6c6c6; }
  code {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    background: #262626; color: #f4f4f4; padding: .1rem .35rem; font-size: .9em;
  }
  .foot { margin: 1.5rem 0 0; font-size: .8rem; color: #6f6f6f; }
</style>
</head>
<body>
  <main class="card">
    <p class="brand"><b>uBix Vault</b> &middot; Secrets Manager</p>
    <span class="pill">Coming soon</span>
    <h1>Admin Portal</h1>
    <p>A web console for managing secrets, policies, tokens, and leases is on the way.</p>
    <p>In the meantime, use the HTTP API under <code>/v1/</code> or the
       <code>ubixvault operator</code> CLI.</p>
    <p class="foot">If you reached this page by accident, you are talking to a uBix Vault server.</p>
  </main>
</body>
</html>
`
