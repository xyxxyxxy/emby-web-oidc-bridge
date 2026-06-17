package handler

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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

			// Remove Accept-Encoding so the backend sends uncompressed
			// responses. ModifyResponse needs to read and modify raw HTML;
			// the downstream reverse proxy (Caddy/Nginx) will re-compress
			// for the client.
			req.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Only modify 2xx HTML responses.
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return nil
			}
			contentType := resp.Header.Get("Content-Type")
			if !strings.Contains(strings.ToLower(contentType), "text/html") {
				return nil
			}

			// Read body.
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()

			// Find <head> case-insensitive.
			lowered := bytes.ToLower(body)
			idx := bytes.Index(lowered, []byte("<head>"))
			if idx < 0 {
				slog.Warn("watchparty: no <head> found, skipping script injection", "path", resp.Request.URL.Path)
				resp.Body = io.NopCloser(bytes.NewReader(body))
				return nil
			}

			// Inject script immediately after <head>.
			insertPos := idx + len("<head>")
			scriptTag := []byte("<script>" + watchpartyAutoLoginScript + "</script>")

			modified := make([]byte, 0, len(body)+len(scriptTag))
			modified = append(modified, body[:insertPos]...)
			modified = append(modified, scriptTag...)
			modified = append(modified, body[insertPos:]...)

			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.Header.Del("Content-Length")
			resp.ContentLength = int64(len(modified))

			return nil
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
