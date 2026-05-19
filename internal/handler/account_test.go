package handler_test

import (
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

func TestAccount_MissingEmailHeader_Returns401(t *testing.T) {
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
	req.Header.Set("X-Forwarded-Email", "unknown@example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAccount_ValidUser_RendersCredentials(t *testing.T) {
	database := setupTestDB(t)

	err := database.InsertUser("alice@example.com", "emby123", "abc12def")
	if err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}

	h := handler.Account(database)

	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	if !strings.Contains(body, "alice@example.com") {
		t.Error("response body does not contain user email")
	}
	if !strings.Contains(body, "abc12def") {
		t.Error("response body does not contain user password")
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected Content-Type text/html, got %q", contentType)
	}
}
