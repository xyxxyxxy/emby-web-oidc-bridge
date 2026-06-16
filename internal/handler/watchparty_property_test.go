package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

// Feature: emby-watchparty-support, Property 3: Watchparty proxy path preservation
// **Validates: Requirements 2.2**
func TestWatchpartyProxyPathPreservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random sub-path under /watchparty/
		numSegments := rapid.IntRange(1, 5).Draw(t, "numSegments")
		segments := make([]string, numSegments)
		for i := range segments {
			segments[i] = rapid.StringMatching(`[a-zA-Z0-9._~-]{1,20}`).Draw(t, "segment")
		}
		subPath := "/watchparty/" + strings.Join(segments, "/")

		// Create a mock backend that records the received request path.
		var receivedPath string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath = r.URL.Path
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ok"))
		}))
		defer backend.Close()

		// Create the watchparty proxy handler targeting the mock backend.
		proxyHandler := handler.WatchpartyProxy(backend.URL)

		// Create a test server wrapping the proxy.
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set a username in context (required by the handler).
			ctx := handler.WithAuthUsername(r.Context(), "testuser")
			proxyHandler.ServeHTTP(w, r.WithContext(ctx))
		}))
		defer proxy.Close()

		// Make a request to the proxy with the generated path.
		resp, err := http.Get(proxy.URL + subPath)
		if err != nil {
			t.Fatalf("request failed: %v", err)
			return
		}
		_ = resp.Body.Close()

		// Assert the mock backend received the exact same path.
		if receivedPath != subPath {
			t.Fatalf("path not preserved: sent %q, backend received %q", subPath, receivedPath)
		}
	})
}

// Feature: emby-watchparty-support, Property 4: HTML response username injection with safe encoding
// **Validates: Requirements 3.1, 3.3**
func TestHTMLUsernameInjectionWithSafeEncoding(t *testing.T) {
	// scriptRe extracts the JSON-encoded value from the injected localStorage script.
	scriptRe := regexp.MustCompile(`<script>localStorage\.setItem\('emby-watchparty-username', (.+?)\);</script>`)

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random username with special characters: quotes, backslashes,
		// angle brackets, Unicode, and control chars.
		username := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`[\"\\<>/\x00-\x1f\x{1f600}-\x{1f64f}]+`),
		).Draw(t, "username")

		// Skip empty usernames since the handler skips injection for them.
		if username == "" {
			return
		}

		// Generate a random HTML body containing a <head> tag.
		headContent := rapid.StringMatching(`[a-zA-Z0-9 <>/="'-]{0,50}`).Draw(t, "headContent")
		bodyContent := rapid.StringMatching(`[a-zA-Z0-9 <>/="'-]{0,100}`).Draw(t, "bodyContent")
		htmlBody := fmt.Sprintf("<html><head>%s</head><body>%s</body></html>", headContent, bodyContent)

		// Create a mock backend that returns the generated HTML.
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(htmlBody))
		}))
		defer backend.Close()

		// Create the watchparty proxy handler.
		proxyHandler := handler.WatchpartyProxy(backend.URL)

		// Create a request with the username set in context.
		req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
		ctx := handler.WithAuthUsername(req.Context(), username)
		req = req.WithContext(ctx)

		// Record the response.
		rec := httptest.NewRecorder()
		proxyHandler.ServeHTTP(rec, req)

		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
			return
		}

		// Verify the script tag is present in the response.
		matches := scriptRe.FindSubmatch(respBody)
		if matches == nil {
			t.Fatalf("injected script not found in response body:\n%s", string(respBody))
			return
		}

		// Extract the JSON-encoded value and decode it.
		jsonValue := matches[1]
		var decoded string
		if err := json.Unmarshal(jsonValue, &decoded); err != nil {
			t.Fatalf("failed to unmarshal JSON value %q: %v", string(jsonValue), err)
			return
		}

		// The decoded string must equal the original username.
		if decoded != username {
			t.Fatalf("decoded username %q does not match original %q", decoded, username)
		}
	})
}

// Feature: emby-watchparty-support, Property 6: Non-HTML response passthrough
// **Validates: Requirements 3.4**
func TestNonHTMLResponsePassthrough(t *testing.T) {
	nonHTMLContentTypes := []string{
		"application/json",
		"text/css",
		"text/plain",
		"image/png",
		"application/javascript",
		"application/octet-stream",
		"text/xml",
		"image/jpeg",
		"application/pdf",
	}

	rapid.Check(t, func(t *rapid.T) {
		// Pick a random non-HTML content type.
		contentType := rapid.SampledFrom(nonHTMLContentTypes).Draw(t, "contentType")

		// Generate a random response body (binary-safe).
		bodyLen := rapid.IntRange(1, 4096).Draw(t, "bodyLen")
		body := rapid.SliceOfN(rapid.Byte(), bodyLen, bodyLen).Draw(t, "body")

		// Create a mock backend that returns the random body with the random content type.
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(body)
		}))
		defer backend.Close()

		// Create the watchparty proxy handler targeting the mock backend.
		proxyHandler := handler.WatchpartyProxy(backend.URL)

		// Create a test server wrapping the proxy.
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := handler.WithAuthUsername(r.Context(), "testuser")
			proxyHandler.ServeHTTP(w, r.WithContext(ctx))
		}))
		defer proxy.Close()

		// Make a request through the proxy.
		resp, err := http.Get(proxy.URL + "/watchparty/somefile")
		if err != nil {
			t.Fatalf("request failed: %v", err)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		// Read the response body from the proxy.
		received, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
			return
		}

		// Verify the response body is byte-for-byte identical (no script injection).
		if !bytes.Equal(received, body) {
			t.Fatalf("body mismatch: expected %d bytes, got %d bytes", len(body), len(received))
		}
	})
}
