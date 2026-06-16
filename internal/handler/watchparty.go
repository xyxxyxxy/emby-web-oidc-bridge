package handler

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

// headTagRe matches an opening <head> or <head ...> tag (case-insensitive).
var headTagRe = regexp.MustCompile(`(?i)<head(\s[^>]*)?>`)

// WatchpartyProxy returns an http.Handler that reverse-proxies requests to the
// configured watchparty backend. For HTML responses, it injects a script that
// sets the user's display name in localStorage so users are automatically
// identified in watch sessions.
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
		ModifyResponse: func(resp *http.Response) error {
			contentType := resp.Header.Get("Content-Type")
			if !strings.Contains(contentType, "text/html") {
				return nil
			}

			username := AuthUsernameFromContext(resp.Request.Context())
			if username == "" {
				return nil
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()

			encoded := jsStringEncode(username)
			script := fmt.Sprintf(`<script>localStorage.setItem('emby-watchparty-username', %s);</script>`, encoded)

			loc := headTagRe.FindIndex(body)
			if loc == nil {
				slog.Warn("watchparty: <head> tag not found in HTML response, skipping injection",
					"path", resp.Request.URL.Path,
				)
				resp.Body = io.NopCloser(bytes.NewReader(body))
				return nil
			}

			// Inject the script right after the matched <head...> tag.
			var modified []byte
			modified = append(modified, body[:loc[1]]...)
			modified = append(modified, []byte(script)...)
			modified = append(modified, body[loc[1]:]...)

			resp.Body = io.NopCloser(bytes.NewReader(modified))
			resp.ContentLength = int64(len(modified))
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(modified)))

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
