package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
)

// watchpartyBridgeCookie is the name of the short-lived bridge cookie used to
// prevent the login handler from intercepting its own redirect.
const watchpartyBridgeCookie = "_wp_bridge_authed"

const watchpartyUsernameTemplate = `<!DOCTYPE html>
<html>
<head><title>Joining watchparty...</title></head>
<body>
<script>
localStorage.setItem('emby-watchparty-username', %s);
window.location.replace('/watchparty/');
</script>
<noscript><p>JavaScript is required. <a href="/watchparty/">Continue to Watchparty</a></p></noscript>
</body>
</html>`

// watchpartyLoginRequest is the JSON body sent to the watchparty login API.
type watchpartyLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// WatchpartyLogin returns an http.HandlerFunc that:
//  1. Checks for the bridge cookie — if present, proxies through immediately.
//  2. On the first GET request for an HTML page (initial navigation), POSTs
//     credentials to the watchparty login API server-side, forwards the
//     resulting session cookie(s) to the client, sets the bridge cookie to
//     prevent re-entry, and serves a small page that writes
//     emby-watchparty-username to localStorage before redirecting.
//  3. All other requests (assets, API calls) are proxied directly.
func WatchpartyLogin(database *db.DB, watchpartyBackendURL string, proxy http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the bridge cookie is present, the pre-auth redirect has already
		// happened — pass directly to the proxy.
		if _, err := r.Cookie(watchpartyBridgeCookie); err == nil {
			proxy.ServeHTTP(w, r)
			return
		}

		// Only intercept GET requests that look like initial HTML page loads.
		// Asset requests (JS, CSS, images, API calls) go straight to the proxy.
		if !isWatchpartyPageRequest(r) {
			proxy.ServeHTTP(w, r)
			return
		}

		sub := AuthSubFromContext(r.Context())
		username := AuthUsernameFromContext(r.Context())

		if sub == "" || username == "" {
			slog.Warn("watchparty: missing auth context, proxying without pre-auth")
			proxy.ServeHTTP(w, r)
			return
		}

		// Look up the user's password from the database.
		record, err := database.FindUserBySub(sub)
		if err != nil {
			slog.Error("watchparty: database error during pre-auth", "sub", sub, "error", err)
			proxy.ServeHTTP(w, r)
			return
		}
		if record == nil {
			slog.Warn("watchparty: user not found in database, proxying without pre-auth", "sub", sub)
			proxy.ServeHTTP(w, r)
			return
		}

		// POST credentials to the watchparty login endpoint.
		loginURL := watchpartyBackendURL + "/watchparty/api/auth/login"
		sessionCookies, loginErr := watchpartyDoLogin(loginURL, username, record.Password)
		if loginErr != nil {
			slog.Error("watchparty: pre-auth login failed", "sub", sub, "error", loginErr)
			// Fall through — proxy without pre-auth rather than blocking the user.
			proxy.ServeHTTP(w, r)
			return
		}
		slog.Info("watchparty: pre-auth login succeeded", "sub", sub, "cookies", len(sessionCookies))

		// Forward the watchparty session cookie(s) to the client verbatim,
		// preserving all attributes (HttpOnly, SameSite, Path, etc.) exactly
		// as the backend sent them.
		for _, sc := range sessionCookies {
			w.Header().Add("Set-Cookie", sc)
		}

		// Set the short-lived bridge cookie so the redirect target goes straight
		// to the proxy without triggering another login attempt.
		http.SetCookie(w, &http.Cookie{
			Name:     watchpartyBridgeCookie,
			Value:    "1",
			Path:     "/watchparty",
			MaxAge:   30,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Serve the intermediate page that sets localStorage and redirects.
		encoded := jsStringEncode(username)
		page := fmt.Sprintf(watchpartyUsernameTemplate, encoded)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(page))
	}
}

// watchpartyDoLogin POSTs credentials to the watchparty login API and returns
// the raw Set-Cookie header values from the response.
func watchpartyDoLogin(loginURL, username, password string) ([]string, error) {
	body, err := json.Marshal(watchpartyLoginRequest{Username: username, Password: password})
	if err != nil {
		return nil, fmt.Errorf("marshalling login request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(loginURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", loginURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("watchparty login returned status %d", resp.StatusCode)
	}

	// Log response to aid diagnosing missing cookies.
	cookieCount := len(resp.Header["Set-Cookie"])
	slog.Info("watchparty: login POST response", "status", resp.StatusCode, "set_cookie_count", cookieCount)
	if cookieCount == 0 {
		slog.Warn("watchparty: login returned no Set-Cookie headers", "response_headers", resp.Header)
	}

	// Return raw Set-Cookie header values so attributes (HttpOnly, SameSite,
	// Path, etc.) are preserved exactly as the backend sent them.
	return resp.Header["Set-Cookie"], nil
}

// WatchpartyProxy returns an http.Handler that reverse-proxies requests to the
// configured watchparty backend without modifying responses.
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

// isWatchpartyPageRequest returns true for GET requests that represent an
// initial HTML page navigation — i.e. paths without a file extension that
// look like app routes (/, /party/CODE, /login, etc.).
// Asset requests (*.js, *.css, *.png, API calls under /api/) go straight
// to the proxy and should not trigger the pre-auth flow.
func isWatchpartyPageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	path := r.URL.Path
	// API calls are never page navigations.
	if strings.HasPrefix(path, "/watchparty/api/") {
		return false
	}
	// Paths with a file extension are assets.
	lastSeg := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		lastSeg = path[idx+1:]
	}
	return !strings.Contains(lastSeg, ".")
}
