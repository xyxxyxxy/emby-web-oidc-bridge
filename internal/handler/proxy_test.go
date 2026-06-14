package handler_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

func TestProxy_ForwardsRequestToEmby(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Path", r.URL.Path)
		w.Header().Set("X-Backend-Query", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	proxy := handler.Proxy(backend.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/some/path?key=value", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "backend response" {
		t.Fatalf("expected 'backend response', got %q", body)
	}
	if got := rec.Header().Get("X-Backend-Path"); got != "/some/path" {
		t.Fatalf("expected path '/some/path', got %q", got)
	}
	if got := rec.Header().Get("X-Backend-Query"); got != "key=value" {
		t.Fatalf("expected query 'key=value', got %q", got)
	}
}

func TestProxy_PreservesRequestHeaders(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := handler.Proxy(backend.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if got := receivedHeaders.Get("X-Custom-Header"); got != "custom-value" {
		t.Fatalf("expected X-Custom-Header 'custom-value', got %q", got)
	}
	if got := receivedHeaders.Get("Accept"); got != "application/json" {
		t.Fatalf("expected Accept 'application/json', got %q", got)
	}
}

func TestProxy_PreservesRequestBody(t *testing.T) {
	var receivedBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := handler.Proxy(backend.URL, nil)

	bodyContent := `{"username":"test@example.com","password":"abc12345"}`
	req := httptest.NewRequest(http.MethodPost, "/Users/AuthenticateByName", strings.NewReader(bodyContent))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if receivedBody != bodyContent {
		t.Fatalf("expected body %q, got %q", bodyContent, receivedBody)
	}
}

func TestProxy_ForwardsAuthTokenFromContext(t *testing.T) {
	var receivedToken string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Emby-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := handler.Proxy(backend.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	ctx := handler.WithAuthToken(req.Context(), "test-access-token-123")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if receivedToken != "test-access-token-123" {
		t.Fatalf("expected X-Emby-Token 'test-access-token-123', got %q", receivedToken)
	}
}

func TestProxy_NoTokenWhenContextEmpty(t *testing.T) {
	var hasToken bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasToken = r.Header.Get("X-Emby-Token") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := handler.Proxy(backend.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if hasToken {
		t.Fatal("expected no X-Emby-Token header when context has no token")
	}
}

func TestProxy_InvalidURL(t *testing.T) {
	proxy := handler.Proxy("://invalid-url", nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for invalid URL, got %d", rec.Code)
	}
}

func TestProxy_WithPathPrefix(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Emby is often at a path like /emby
	proxy := handler.Proxy(backend.URL+"/emby", nil)

	req := httptest.NewRequest(http.MethodGet, "/Items/123", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if receivedPath != "/emby/Items/123" {
		t.Fatalf("expected path '/emby/Items/123', got %q", receivedPath)
	}
}

func TestWithAuthToken_And_AuthTokenFromContext(t *testing.T) {
	ctx := context.Background()

	// No token set
	if got := handler.AuthTokenFromContext(ctx); got != "" {
		t.Fatalf("expected empty token from empty context, got %q", got)
	}

	// Set token
	ctx = handler.WithAuthToken(ctx, "my-token")
	if got := handler.AuthTokenFromContext(ctx); got != "my-token" {
		t.Fatalf("expected 'my-token', got %q", got)
	}
}

func TestProxy_401ResponseEvictsSession(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate Emby rejecting an invalid/expired token.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer backend.Close()

	var invalidatedSub string
	invalidate := func(sub string) {
		invalidatedSub = sub
	}

	proxy := handler.Proxy(backend.URL, invalidate)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	ctx := handler.WithAuthSub(req.Context(), "sub-deleted-user")
	ctx = handler.WithAuthToken(ctx, "stale-token")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	// The 401 should still be returned to the client.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// The invalidate callback should have been called with the correct sub.
	if invalidatedSub != "sub-deleted-user" {
		t.Errorf("expected invalidated sub %q, got %q", "sub-deleted-user", invalidatedSub)
	}
}

func TestProxy_401WithoutSubDoesNotPanic(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer backend.Close()

	var invalidateCalled bool
	invalidate := func(sub string) {
		invalidateCalled = true
	}

	proxy := handler.Proxy(backend.URL, invalidate)

	// Request without sub in context.
	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// Should not call invalidate when sub is empty.
	if invalidateCalled {
		t.Error("invalidateSession should not be called when sub is empty in context")
	}
}

func TestProxy_NonUnauthorizedDoesNotEvict(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403, not 401.
	}))
	defer backend.Close()

	var invalidateCalled bool
	invalidate := func(sub string) {
		invalidateCalled = true
	}

	proxy := handler.Proxy(backend.URL, invalidate)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	ctx := handler.WithAuthSub(req.Context(), "sub-some-user")
	ctx = handler.WithAuthToken(ctx, "some-token")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	// 403 should NOT trigger session invalidation.
	if invalidateCalled {
		t.Error("invalidateSession should not be called for non-401 responses")
	}
}

func TestProxy_NilInvalidateDoesNotPanicOn401(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer backend.Close()

	// Pass nil invalidateSession — should not panic.
	proxy := handler.Proxy(backend.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	ctx := handler.WithAuthSub(req.Context(), "sub-nil-test")
	ctx = handler.WithAuthToken(ctx, "some-token")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWithAuthSub_And_AuthSubFromContext(t *testing.T) {
	ctx := context.Background()

	// No sub set.
	if got := handler.AuthSubFromContext(ctx); got != "" {
		t.Fatalf("expected empty sub from empty context, got %q", got)
	}

	// Set sub.
	ctx = handler.WithAuthSub(ctx, "my-oidc-sub")
	if got := handler.AuthSubFromContext(ctx); got != "my-oidc-sub" {
		t.Fatalf("expected 'my-oidc-sub', got %q", got)
	}
}
