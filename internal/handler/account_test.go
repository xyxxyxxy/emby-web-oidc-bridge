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
	t.Cleanup(func() { database.Close() })
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

func TestAccount_UserNotFound_Returns404(t *testing.T) {
	database := setupTestDB(t)
	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Sub", "unknown-sub")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAccount_ValidUser_RendersCredentials(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("sub-alice", "Alice", "alice@example.com", "emby123", "abc12def")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-alice")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	// Username should be the name field (not email).
	if !strings.Contains(body, "Alice") {
		t.Error("response body does not contain username (name)")
	}
	if !strings.Contains(body, "abc12def") {
		t.Error("response body does not contain user password")
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}
}

func TestAccount_FallsBackToEmailWhenNameEmpty(t *testing.T) {
	database := setupTestDB(t)

	// Insert user with empty name — email should be used as username.
	err := database.InsertUser("sub-noname", "", "noname@example.com", "emby-nn", "nnpass99")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-noname")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "noname@example.com") {
		t.Error("response body does not contain email as fallback username")
	}
	if !strings.Contains(body, "nnpass99") {
		t.Error("response body does not contain user password")
	}
}

func TestAccount_XAuthRequestSubFallback(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("sub-fallback", "Fallback", "fallback@example.com", "emby-fb", "fbpass99")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	// Use X-Auth-Request-Sub instead of X-Forwarded-Sub.
	req.Header.Set("X-Auth-Request-Sub", "sub-fallback")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Fallback") {
		t.Error("response body does not contain username from X-Auth-Request-Sub fallback")
	}
	if !strings.Contains(body, "fbpass99") {
		t.Error("response body does not contain user password")
	}
}

func TestAccount_SubFromJWT(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("jwt-sub-123", "JWT User", "jwt@example.com", "emby-jwt", "jwtpass")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	// Build a JWT with a sub claim.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"jwt-sub-123","email":"jwt@example.com"}`))
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
	if !strings.Contains(body, "JWT User") {
		t.Error("response body does not contain username")
	}
	if !strings.Contains(body, "jwtpass") {
		t.Error("response body does not contain user password")
	}
}
