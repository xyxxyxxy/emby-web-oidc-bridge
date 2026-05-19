package handler

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// contextKey is an unexported type for context keys in this package.
type contextKey struct{ name string }

// authTokenKey is the context key for the Emby auth token set by the auth middleware.
var authTokenKey = &contextKey{"auth-token"}

// WithAuthToken returns a new context with the given Emby auth token stored.
// This is intended to be called by the auth middleware after authenticating with Emby.
func WithAuthToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authTokenKey, token)
}

// AuthTokenFromContext retrieves the Emby auth token from the request context.
// Returns an empty string if no token is present.
func AuthTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(authTokenKey).(string)
	return token
}

// Proxy returns an http.Handler that reverse-proxies requests to Emby.
// It uses net/http/httputil.ReverseProxy with a Director function that preserves
// request headers and body content, and forwards the authenticated session token.
func Proxy(embyURL string) http.Handler {
	target, err := url.Parse(embyURL)
	if err != nil {
		slog.Error("proxy: invalid emby URL", "url", embyURL, "error", err)
		// Return a handler that always returns 500 if the URL is invalid.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		})
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			// Preserve the original request path and query.
			// If the target URL has a path prefix, prepend it.
			if target.Path != "" && target.Path != "/" {
				req.URL.Path = target.Path + req.URL.Path
			}

			// Forward the authenticated session token if present in context.
			token := AuthTokenFromContext(req.Context())
			if token != "" {
				req.Header.Set("X-Emby-Token", token)
			}
		},
	}

	return proxy
}
