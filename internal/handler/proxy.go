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
var authUserIDKey = &contextKey{"auth-user-id"}
var authServerIDKey = &contextKey{"auth-server-id"}
var authSubKey = &contextKey{"auth-sub"}
var authUsernameKey = &contextKey{"auth-username"}

// WithAuthToken returns a new context with the given Emby auth token stored.
// This is intended to be called by the auth middleware after authenticating with Emby.
func WithAuthToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authTokenKey, token)
}

// WithAuthSession stores the full auth session (token, user ID, server ID) in context.
func WithAuthSession(ctx context.Context, token, userID, serverID string) context.Context {
	ctx = context.WithValue(ctx, authTokenKey, token)
	ctx = context.WithValue(ctx, authUserIDKey, userID)
	ctx = context.WithValue(ctx, authServerIDKey, serverID)
	return ctx
}

// WithAuthSub stores the OIDC subject identifier in context.
// This is used by the proxy to evict the session cache on 401 responses.
func WithAuthSub(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, authSubKey, sub)
}

// AuthTokenFromContext retrieves the Emby auth token from the request context.
// Returns an empty string if no token is present.
func AuthTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(authTokenKey).(string)
	return token
}

// AuthUserIDFromContext retrieves the Emby user ID from the request context.
func AuthUserIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(authUserIDKey).(string)
	return id
}

// AuthServerIDFromContext retrieves the Emby server ID from the request context.
func AuthServerIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(authServerIDKey).(string)
	return id
}

// AuthSubFromContext retrieves the OIDC subject from the request context.
func AuthSubFromContext(ctx context.Context) string {
	sub, _ := ctx.Value(authSubKey).(string)
	return sub
}

// WithAuthUsername stores the resolved OIDC display name in context.
// This is used by the watchparty handler to inject the username into HTML responses.
func WithAuthUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, authUsernameKey, username)
}

// AuthUsernameFromContext retrieves the resolved OIDC display name from the request context.
// Returns an empty string if no username is present.
func AuthUsernameFromContext(ctx context.Context) string {
	u, _ := ctx.Value(authUsernameKey).(string)
	return u
}

// Proxy returns an http.Handler that reverse-proxies requests to Emby.
// It uses net/http/httputil.ReverseProxy with a Director function that preserves
// request headers and body content, and forwards the authenticated session token.
// If invalidateSession is non-nil, the proxy will evict the cached session when
// Emby responds with 401 (indicating the token has been invalidated, e.g. because
// the user was deleted from Emby).
func Proxy(embyURL string, invalidateSession func(string)) http.Handler {
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
		ModifyResponse: func(resp *http.Response) error {
			// If Emby responds with 401, the cached token is invalid (user deleted,
			// session revoked, etc.). Evict the session so the next request triggers
			// fresh authentication via the auth middleware.
			if resp.StatusCode == http.StatusUnauthorized && invalidateSession != nil {
				sub := AuthSubFromContext(resp.Request.Context())
				if sub != "" {
					invalidateSession(sub)
					slog.Warn("proxy: received 401 from Emby, evicted cached session",
						"sub", sub,
						"path", resp.Request.URL.Path,
					)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy: backend error",
				"path", r.URL.Path,
				"method", r.Method,
				"error", err,
			)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return proxy
}
