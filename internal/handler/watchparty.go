package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const watchpartyUsernameTemplate = `<!DOCTYPE html>
<html>
<head><title>Joining watchparty...</title></head>
<body>
<script>
localStorage.setItem('emby-watchparty-username', %s);
window.location.replace('/watchparty/?u=1');
</script>
<noscript><p>JavaScript is required. <a href="/watchparty/?u=1">Continue to Watchparty</a></p></noscript>
</body>
</html>`

// WatchpartySetUsername returns an http.HandlerFunc that serves a small page
// which sets the authenticated user's display name in localStorage and then
// redirects to the actual watchparty UI. This avoids modifying proxied
// responses and keeps the proxy layer simple.
func WatchpartySetUsername() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If ?u=1 is present, the username has already been set — proxy through
		// to the watchparty backend by letting the next handler in the mux take over.
		// This case is handled by route registration order in main.go, so this
		// handler only receives requests without ?u=1.

		username := AuthUsernameFromContext(r.Context())
		if username == "" {
			slog.Warn("watchparty: no username in context, redirecting without setting")
			http.Redirect(w, r, "/watchparty/?u=1", http.StatusFound)
			return
		}

		encoded := jsStringEncode(username)
		page := fmt.Sprintf(watchpartyUsernameTemplate, encoded)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(page))
	}
}

// WatchpartyProxy returns an http.Handler that reverse-proxies requests to the
// configured watchparty backend. It does not modify responses — username
// injection is handled by the separate WatchpartySetUsername handler on the
// initial page load.
func WatchpartyProxy(backendURL string) http.Handler {
	target, err := url.Parse(backendURL)
	if err != nil {
		slog.Error("watchparty: invalid backend URL", "url", backendURL, "error", err)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		})
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// Preserve the request path unchanged — the watchparty service
			// expects the /watchparty/ prefix via APP_PREFIX configuration.
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("watchparty: backend error",
				"path", r.URL.Path,
				"method", r.Method,
				"error", err,
			)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return proxy
}
