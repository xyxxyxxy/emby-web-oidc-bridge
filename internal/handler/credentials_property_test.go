package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

var credentialsDBCounter atomic.Int64

// credentialsDBURI returns a unique in-memory database URI for each test run.
func credentialsDBURI() string {
	n := credentialsDBCounter.Add(1)
	return fmt.Sprintf("file:credpropdb%d?mode=memory&cache=shared", n)
}

// Feature: watchparty-v2-auto-login, Property 1: Credentials endpoint round-trip correctness
// **Validates: Requirements 1.1, 1.3, 1.8, 1.9, 6.4**
func TestCredentials_RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate arbitrary values
		sub := rapid.StringMatching(`[a-z0-9]{8,20}`).Draw(t, "sub")
		username := rapid.StringMatching(`[A-Za-z][A-Za-z0-9 ]{2,19}`).Draw(t, "username")
		password := rapid.StringMatching(`[a-zA-Z0-9!@#]{8,32}`).Draw(t, "password")
		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		userID := rapid.StringMatching(`[a-f0-9]{32}`).Draw(t, "userID")

		// Open a unique in-memory DB and seed the user record
		database, err := db.Open(credentialsDBURI())
		if err != nil {
			t.Fatalf("db.Open failed: %v", err)
			return
		}
		defer func() { _ = database.Close() }()

		err = database.InsertUser(sub, username, email, userID, password)
		if err != nil {
			t.Fatalf("InsertUser failed: %v", err)
			return
		}

		// Build an HTTP request with the sub and username in context
		req := httptest.NewRequest(http.MethodGet, "/api/credentials", nil)
		ctx := handler.WithAuthSub(req.Context(), sub)
		ctx = handler.WithAuthUsername(ctx, username)
		req = req.WithContext(ctx)

		// Call the handler
		rec := httptest.NewRecorder()
		h := handler.Credentials(database)
		h.ServeHTTP(rec, req)

		// Assert status 200
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
			return
		}

		// Assert Content-Type header
		ct := rec.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Fatalf("Content-Type: got %q, want %q", ct, "application/json")
			return
		}

		// Assert Cache-Control header
		cc := rec.Header().Get("Cache-Control")
		if cc != "no-store" {
			t.Fatalf("Cache-Control: got %q, want %q", cc, "no-store")
			return
		}

		// Assert JSON body
		var resp struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		err = json.NewDecoder(rec.Body).Decode(&resp)
		if err != nil {
			t.Fatalf("JSON decode failed: %v", err)
			return
		}

		if resp.Username != username {
			t.Fatalf("username: got %q, want %q", resp.Username, username)
		}
		if resp.Password != password {
			t.Fatalf("password: got %q, want %q", resp.Password, password)
		}
	})
}

// Feature: watchparty-v2-auto-login, Property 3: Credentials endpoint error responses
// **Validates: Requirements 1.5, 1.6, 1.8, 1.9, 6.5**
func TestCredentials_ErrorResponses(t *testing.T) {
	t.Run("missing_sub_returns_401", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			database, err := db.Open(credentialsDBURI())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
				return
			}
			defer func() { _ = database.Close() }()

			h := handler.Credentials(database)

			// Create request with NO AuthSub in context (empty context)
			req := httptest.NewRequest(http.MethodGet, "/api/credentials", nil)
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			// Assert status 401
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected status 401, got %d", rec.Code)
				return
			}

			// Assert Content-Type header
			ct := rec.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Fatalf("expected Content-Type application/json, got %q", ct)
				return
			}

			// Assert Cache-Control header
			cc := rec.Header().Get("Cache-Control")
			if cc != "no-store" {
				t.Fatalf("expected Cache-Control no-store, got %q", cc)
				return
			}

			// Assert JSON error body
			var errResp struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode response body: %v", err)
				return
			}
			if errResp.Error != "missing authentication context" {
				t.Fatalf("expected error %q, got %q", "missing authentication context", errResp.Error)
			}
		})
	})

	t.Run("nonexistent_sub_returns_404", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			database, err := db.Open(credentialsDBURI())
			if err != nil {
				t.Fatalf("Open failed: %v", err)
				return
			}
			defer func() { _ = database.Close() }()

			h := handler.Credentials(database)

			// Generate a random sub that does NOT exist in the empty database
			randomSub := rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "sub")

			// Create request with AuthSub set in context but user not in DB
			req := httptest.NewRequest(http.MethodGet, "/api/credentials", nil)
			ctx := handler.WithAuthSub(req.Context(), randomSub)
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			// Assert status 404
			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected status 404, got %d (sub=%q)", rec.Code, randomSub)
				return
			}

			// Assert Content-Type header
			ct := rec.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Fatalf("expected Content-Type application/json, got %q", ct)
				return
			}

			// Assert Cache-Control header
			cc := rec.Header().Get("Cache-Control")
			if cc != "no-store" {
				t.Fatalf("expected Cache-Control no-store, got %q", cc)
				return
			}

			// Assert JSON error body
			var errResp struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
				t.Fatalf("failed to decode response body: %v", err)
				return
			}
			if errResp.Error != "user not found" {
				t.Fatalf("expected error %q, got %q", "user not found", errResp.Error)
			}
		})
	})
}
