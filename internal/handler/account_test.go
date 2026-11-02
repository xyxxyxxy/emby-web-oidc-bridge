package handler_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

var testDBCounter atomic.Int64

func setupTestDB(t *testing.T) *db.DB {
	t.Helper()
	n := testDBCounter.Add(1)
	uri := fmt.Sprintf("file:handlertest%d?mode=memory&cache=shared", n)
	database, err := db.Open(uri)
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestAccount_MissingSub_Returns401(t *testing.T) {
	database := setupTestDB(t)
	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestAccount_MissingPreferredUsername_Returns401(t *testing.T) {
	database := setupTestDB(t)
	err := database.InsertUser("sub-alice", "emby123", "abc12def")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}
	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-alice")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestAccount_UserNotFound_Returns404(t *testing.T) {
	database := setupTestDB(t)
	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Sub", "unknown-sub")
	req.Header.Set("X-Forwarded-Preferred-Username", "unknown")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAccount_ValidUser_RendersCredentials(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("sub-alice", "emby123", "abc12def")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-alice")
	req.Header.Set("X-Forwarded-Preferred-Username", "Alice")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	if !strings.Contains(body, "Alice") {
		t.Error("response body does not contain preferred_username")
	}
	if !strings.Contains(body, "abc12def") {
		t.Error("response body does not contain user password")
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}
}

func TestAccount_XAuthRequestSubFallback(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("sub-fallback", "emby-fb", "fbpass99")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Auth-Request-Sub", "sub-fallback")
	req.Header.Set("X-Auth-Request-Preferred-Username", "Fallback")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Fallback") {
		t.Error("response body does not contain preferred_username")
	}
	if !strings.Contains(body, "fbpass99") {
		t.Error("response body does not contain user password")
	}
}

func TestAccount_SubFromJWT(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("jwt-sub-123", "emby-jwt", "jwtpass")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"jwt-sub-123","preferred_username":"JWTUser"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jwtToken := header + "." + payload + "." + signature

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "JWTUser") {
		t.Error("response body does not contain preferred_username from JWT")
	}
	if !strings.Contains(body, "jwtpass") {
		t.Error("response body does not contain user password")
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
