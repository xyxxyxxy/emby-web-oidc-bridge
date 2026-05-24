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

	proxy := handler.Proxy(backend.URL)

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

	proxy := handler.Proxy(backend.URL)

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

	proxy := handler.Proxy(backend.URL)

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

	proxy := handler.Proxy(backend.URL)

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

	proxy := handler.Proxy(backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	if hasToken {
		t.Fatal("expected no X-Emby-Token header when context has no token")
	}
}

func TestProxy_InvalidURL(t *testing.T) {
	proxy := handler.Proxy("://invalid-url")

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
	proxy := handler.Proxy(backend.URL + "/emby")

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
