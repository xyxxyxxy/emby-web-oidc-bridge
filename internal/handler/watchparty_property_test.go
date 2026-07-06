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
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

var watchpartyDBCounter atomic.Int64

// newTestDB opens a unique in-memory SQLite database and optionally seeds one user.
// If sub is empty, the database is returned empty.
func newTestDB(t *testing.T, sub, username, password string) *db.DB {
	t.Helper()
	n := watchpartyDBCounter.Add(1)
	uri := fmt.Sprintf("file:wptestdb%d?mode=memory&cache=shared", n)
	database, err := db.Open(uri)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if sub != "" {
		if err := database.InsertUser(sub, username, "test@example.com", "userid1", password); err != nil {
			t.Fatalf("InsertUser failed: %v", err)
		}
	}
	return database
}

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

// Feature: emby-watchparty-support, Property 4: Login page sets localStorage with safe encoding
// **Validates: Requirements 3.1, 3.3**
func TestWatchpartyLoginPageSafeEncoding(t *testing.T) {
	// scriptRe extracts the JSON-encoded value from the localStorage script in the login page.
	scriptRe := regexp.MustCompile(`localStorage\.setItem\('emby-watchparty-username', (.+?)\);`)

	// Build a fake watchparty login backend that returns 200 OK.
	loginBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer loginBackend.Close()

	// Build a no-op proxy (should not be called when pre-auth succeeds).
	nopProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	// Open DB once for the outer test — rapid runs vary only in username.
	database := newTestDB(t, "testsub", "placeholder", "testpassword")

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random username with special characters: quotes, backslashes,
		// angle brackets, Unicode, and control chars.
		username := rapid.OneOf(
			rapid.String(),
			rapid.StringMatching(`[\"\\<>/\x00-\x1f\x{1f600}-\x{1f64f}]+`),
		).Draw(t, "username")

		// Skip empty usernames since the handler falls through to the proxy.
		if username == "" {
			return
		}

		loginHandler := handler.WatchpartyLogin(database, loginBackend.URL, nopProxy)

		req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
		ctx := handler.WithAuthSub(req.Context(), "testsub")
		ctx = handler.WithAuthUsername(ctx, username)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		loginHandler(rec, req)

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

		// Verify the page redirects to /watchparty/ (no ?u=1).
		if !strings.Contains(string(body), "window.location.replace('/watchparty/')") {
			t.Fatalf("redirect to /watchparty/ not found in response body")
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
		// Pick a random content type.
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

// TestWatchpartyLoginMissingContext verifies that when no auth context is
// present, the handler falls through to the proxy without attempting pre-auth.
func TestWatchpartyLoginMissingContext(t *testing.T) {
	var proxyCalled bool
	nopProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusOK)
	})

	db := newTestDB(t, "", "", "")
	loginHandler := handler.WatchpartyLogin(db, "http://unused", nopProxy)

	req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
	// No auth context set.

	rec := httptest.NewRecorder()
	loginHandler(rec, req)

	if !proxyCalled {
		t.Fatal("expected proxy to be called when auth context is missing")
	}
}

// TestWatchpartyLoginBridgeCookieBypassesPreAuth verifies that when the bridge
// cookie is present, the handler proxies immediately without attempting login.
func TestWatchpartyLoginBridgeCookieBypassesPreAuth(t *testing.T) {
	var proxyCalled bool
	nopProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusOK)
	})

	db := newTestDB(t, "sub1", "user1", "pass1")
	loginHandler := handler.WatchpartyLogin(db, "http://unused", nopProxy)

	req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
	req.AddCookie(&http.Cookie{Name: "_wp_bridge_authed", Value: "1"})
	ctx := handler.WithAuthSub(req.Context(), "sub1")
	ctx = handler.WithAuthUsername(ctx, "user1")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	loginHandler(rec, req)

	if !proxyCalled {
		t.Fatal("expected proxy to be called when bridge cookie is present")
	}
}

// TestWatchpartyLoginForwardsSessionCookies verifies that session cookies from
// the watchparty login response are forwarded to the client.
func TestWatchpartyLoginForwardsSessionCookies(t *testing.T) {
	loginBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
			Path:  "/watchparty",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer loginBackend.Close()

	nopProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	db := newTestDB(t, "sub1", "user1", "pass1")
	loginHandler := handler.WatchpartyLogin(db, loginBackend.URL, nopProxy)

	req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
	ctx := handler.WithAuthSub(req.Context(), "sub1")
	ctx = handler.WithAuthUsername(ctx, "user1")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	loginHandler(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	// Look for the forwarded session cookie.
	var foundSession, foundBridge bool
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value == "abc123" {
			foundSession = true
		}
		if c.Name == "_wp_bridge_authed" {
			foundBridge = true
		}
	}

	if !foundSession {
		t.Fatal("expected session cookie to be forwarded to client")
	}
	if !foundBridge {
		t.Fatal("expected bridge cookie to be set")
	}
}

// TestWatchpartyLoginBackendFailureFallsThrough verifies that when the watchparty
// login endpoint returns a non-2xx status, the handler falls through to the proxy.
func TestWatchpartyLoginBackendFailureFallsThrough(t *testing.T) {
	loginBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer loginBackend.Close()

	var proxyCalled bool
	nopProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusOK)
	})

	db := newTestDB(t, "sub1", "user1", "wrongpassword")
	loginHandler := handler.WatchpartyLogin(db, loginBackend.URL, nopProxy)

	req := httptest.NewRequest(http.MethodGet, "/watchparty/", nil)
	ctx := handler.WithAuthSub(req.Context(), "sub1")
	ctx = handler.WithAuthUsername(ctx, "user1")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	loginHandler(rec, req)

	if !proxyCalled {
		t.Fatal("expected proxy to be called when login backend fails")
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
