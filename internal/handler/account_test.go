package handler_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

func TestExtractSubFromRequest_XForwardedSub(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-from-header")

	sub := handler.ExtractSubFromRequest(req)
	if sub != "sub-from-header" {
		t.Errorf("expected 'sub-from-header', got %q", sub)
	}
}

func TestExtractSubFromRequest_XAuthRequestSub(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Auth-Request-Sub", "sub-auth-request")

	sub := handler.ExtractSubFromRequest(req)
	if sub != "sub-auth-request" {
		t.Errorf("expected 'sub-auth-request', got %q", sub)
	}
}

func TestExtractSubFromRequest_JWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"jwt-sub-123"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jwtToken := header + "." + payload + "." + signature

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	sub := handler.ExtractSubFromRequest(req)
	if sub != "jwt-sub-123" {
		t.Errorf("expected 'jwt-sub-123', got %q", sub)
	}
}

func TestExtractSubFromRequest_NoHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	sub := handler.ExtractSubFromRequest(req)
	if sub != "" {
		t.Errorf("expected empty string, got %q", sub)
	}
}

func TestExtractPreferredUsernameFromRequest_Header(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Preferred-Username", "alice")

	got := handler.ExtractPreferredUsernameFromRequest(req)
	if got != "alice" {
		t.Errorf("expected alice, got %q", got)
	}
}

func TestExtractPreferredUsernameFromRequest_JWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"preferred_username":"bob"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jwtToken := header + "." + payload + "." + signature

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	got := handler.ExtractPreferredUsernameFromRequest(req)
	if got != "bob" {
		t.Errorf("expected bob, got %q", got)
	}
}
