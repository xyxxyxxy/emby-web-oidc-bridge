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

// Feature: emby-watchparty-support, Property 4: Username redirect page sets localStorage with safe encoding
// **Validates: Requirements 3.1, 3.3**
func TestWatchpartyUsernamePageSafeEncoding(t *testing.T) {
	// scriptRe extracts the JSON-encoded value from the localStorage script in the redirect page.
	scriptRe := regexp.MustCompile(`localStorage\.setItem\('emby-watchparty-username', (.+?)\);`)

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random username with special characters: quotes, backslashes,
		// angle brackets, Unicode, and control chars.
		username := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`[\"\\<>/\x00-\x1f\x{1f600}-\x{1f64f}]+`),
		).Draw(t, "username")

		// Skip empty usernames since the handler redirects without setting for them.
		if username == "" {
			return
		}

		// Create a request to /watchparty/ (without ?u=1) with the username in context.
		req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
		ctx := handler.WithAuthUsername(req.Context(), username)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.WatchpartySetUsername()(rec, req)

		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
			return
		}

		// Verify the script contains the localStorage.setItem call.
		matches := scriptRe.FindSubmatch(body)
		if matches == nil {
			t.Fatalf("localStorage.setItem not found in response body:\n%s", string(body))
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

		// Verify the page contains a redirect to /watchparty/?u=1
		if !strings.Contains(string(body), "/watchparty/?u=1") {
			t.Fatalf("redirect to /watchparty/?u=1 not found in response body")
		}
	})
}

// Feature: emby-watchparty-support, Property 6: Proxy response passthrough (no modification)
// **Validates: Requirements 3.4**
func TestWatchpartyProxyResponsePassthrough(t *testing.T) {
	contentTypes := []string{
		"application/json",
		"text/css",
		"text/plain",
		"text/html",
		"text/html; charset=utf-8",
		"image/png",
		"application/javascript",
		"application/octet-stream",
	}

	rapid.Check(t, func(t *rapid.T) {
		// Pick a random content type (including text/html — proxy should NOT modify).
		contentType := rapid.SampledFrom(contentTypes).Draw(t, "contentType")

		// Generate a random response body (binary-safe).
		bodyLen := rapid.IntRange(1, 4096).Draw(t, "bodyLen")
		body := rapid.SliceOfN(rapid.Byte(), bodyLen, bodyLen).Draw(t, "body")

		// Create a mock backend that returns the random body.
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(body)
		}))
		defer backend.Close()

		// Create the watchparty proxy handler.
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

		// Verify the response body is byte-for-byte identical (no modification).
		if !bytes.Equal(received, body) {
			t.Fatalf("body mismatch for content-type %q: expected %d bytes, got %d bytes",
				contentType, len(body), len(received))
		}
	})
}

// TestWatchpartySetUsernameEmptyUsername verifies that when no username is in
// context, the handler redirects to /watchparty/?u=1 without serving the
// localStorage-setting page.
func TestWatchpartySetUsernameEmptyUsername(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
	// No username in context.

	rec := httptest.NewRecorder()
	handler.WatchpartySetUsername()(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.StatusCode)
		return
	}

	location := resp.Header.Get("Location")
	if location != "/watchparty/?u=1" {
		t.Fatalf("expected redirect to /watchparty/?u=1, got %q", location)
	}
}

// TestWatchpartyProxyInvalidBackendURL verifies that WatchpartyProxy returns
// 500 when given an unparseable backend URL.
func TestWatchpartyProxyInvalidBackendURL(t *testing.T) {
	proxyHandler := handler.WatchpartyProxy("://not-a-url")

	req := httptest.NewRequest(http.MethodGet, "/watchparty/test", nil)
	rec := httptest.NewRecorder()
	proxyHandler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

// TestWatchpartyProxyBackendUnreachable verifies that the proxy returns 502
// when the backend is not reachable.
func TestWatchpartyProxyBackendUnreachable(t *testing.T) {
	// Use a URL that will fail to connect (closed port).
	proxyHandler := handler.WatchpartyProxy("http://127.0.0.1:1")

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := handler.WithAuthUsername(r.Context(), "testuser")
		proxyHandler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/watchparty/test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

// Feature: watchparty-v2-auto-login, Property 2: Script injection conditional correctness
// **Validates: Requirements 2.1, 3.1, 3.2, 3.4, 3.5, 6.2**
func TestWatchpartyProxy_ScriptInjection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate test parameters.
		// Note: 204 (No Content) is excluded because Go's HTTP transport discards
		// the body for 204 responses per HTTP spec, making body assertions invalid.
		statusCode := rapid.SampledFrom([]int{200, 201, 301, 400, 404, 500}).Draw(t, "status")
		contentType := rapid.SampledFrom([]string{
			"text/html", "text/html; charset=utf-8", "TEXT/HTML",
			"application/json", "text/css", "application/javascript",
		}).Draw(t, "contentType")
		hasHead := rapid.Bool().Draw(t, "hasHead")
		headTag := rapid.SampledFrom([]string{"<head>", "<HEAD>", "<Head>"}).Draw(t, "headTag")

		// Build response body.
		var body string
		if hasHead {
			body = "<!DOCTYPE html><html>" + headTag + "<title>Test</title></head><body><p>Hello</p></body></html>"
		} else {
			body = "<!DOCTYPE html><html><body><p>Hello</p></body></html>"
		}

		// Create backend server that returns the generated response.
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte(body))
		}))
		defer backend.Close()

		// Create proxy and make request.
		proxy := handler.WatchpartyProxy(backend.URL)
		req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, req)

		// Determine if injection should happen.
		isHTML := strings.Contains(strings.ToLower(contentType), "text/html")
		is2xx := statusCode >= 200 && statusCode < 300
		shouldInject := is2xx && isHTML && hasHead

		responseBody := rec.Body.String()

		if shouldInject {
			// Style tag and script should both be present.
			if !strings.Contains(responseBody, "<style id=\"_ewp_bridge_hide\">") {
				t.Fatalf("expected style tag injection but none found")
				return
			}
			if !strings.Contains(responseBody, "<script>") {
				t.Fatalf("expected script injection but none found")
				return
			}
			// Style tag positioned immediately after <head> (case-insensitive check).
			headIdx := strings.Index(strings.ToLower(responseBody), "<head>")
			styleIdx := strings.Index(responseBody, "<style id=\"_ewp_bridge_hide\">")
			if headIdx < 0 {
				t.Fatalf("no <head> found in response")
				return
			}
			if styleIdx != headIdx+len("<head>") {
				t.Fatalf("style not positioned immediately after <head>: headIdx=%d, styleIdx=%d", headIdx, styleIdx)
				return
			}
			// Content-Length should be absent (deleted by ModifyResponse).
			if rec.Header().Get("Content-Length") != "" {
				t.Fatalf("Content-Length should be removed after injection")
				return
			}
			// No password literals in the injected script (validates 6.2).
			if strings.Contains(responseBody, `"password"`) {
				t.Fatalf("injected script should not contain password literals")
				return
			}
		} else {
			// Body should be unmodified.
			if responseBody != body {
				t.Fatalf("body was modified when it should not have been:\nexpected: %q\ngot:      %q", body, responseBody)
				return
			}
		}
	})
}
