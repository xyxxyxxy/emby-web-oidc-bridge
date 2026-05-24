package handler_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

var propertyDBCounter atomic.Int64

func propertyDBURI() string {
	n := propertyDBCounter.Add(1)
	return fmt.Sprintf("file:accountpropdb%d?mode=memory&cache=shared", n)
}

// Feature: emby-auth-bridge, Property 5: Account page credential display
// **Validates: Requirements 8.1, 8.2**
func TestAccountPageCredentialDisplay(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		database, err := db.Open(propertyDBURI())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer func() { _ = database.Close() }()

		sub := rapid.StringMatching(`[a-z0-9]{8,20}`).Draw(t, "sub")
		name := rapid.StringMatching(`[A-Za-z]{3,15}`).Draw(t, "name")
		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		password := rapid.StringMatching(`[a-z0-9]{8}`).Draw(t, "password")
		userID := rapid.StringMatching(`[a-f0-9]{32}`).Draw(t, "userID")

		err = database.InsertUser(sub, name, email, userID, password)
		if err != nil {
			t.Fatalf("InsertUser failed: %v", err)
		}

		h := handler.Account(database)

		req := httptest.NewRequest(http.MethodGet, "/account", nil)
		req.Header.Set("X-Forwarded-Sub", sub)
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		body := rec.Body.String()

		// Username should be the name (since it's non-empty).
		if !strings.Contains(body, name) {
			t.Fatalf("response body does not contain name %q", name)
		}
		if !strings.Contains(body, password) {
			t.Fatalf("response body does not contain password %q", password)
		}
	})
}
