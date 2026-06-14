package handler

import (
	"log/slog"
	"net/http"
)

// Logout returns an http.HandlerFunc that intercepts Emby's session logout request.
// Instead of forwarding the logout to Emby (which would invalidate the token while
// the bridge still has it cached), this handler:
// 1. Evicts the user's session from the bridge cache via the provided invalidate function
// 2. Redirects the user back to the root, which triggers re-authentication via OIDC
//
// This prevents the bug where the bridge continues serving a stale (invalidated)
// access token after the user clicks "Sign Out" in the Emby web UI.
func Logout(extractSub func(*http.Request) string, invalidateSession func(string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := extractSub(r)
		if sub != "" {
			invalidateSession(sub)
			slog.Info("logout: evicted cached session",
				"sub", sub,
			)
		} else {
			slog.Warn("logout: could not determine user sub, cache not evicted")
		}

		// Redirect to root which will re-trigger OIDC auth and produce a fresh session.
		// Use 302 so the browser does a GET (the original request is POST).
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
