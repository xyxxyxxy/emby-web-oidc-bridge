package middleware_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/middleware"
)

var testDBCounter atomic.Int64

// testTemplatePolicy is a valid JSON policy used as the templatePolicy argument in tests.
var testTemplatePolicy = []byte(`{"IsDisabled":true,"IsHidden":true,"EnableUserPreferenceAccess":true}`)

// testDBURI returns a unique in-memory database URI for each test.
func testDBURI() string {
	n := testDBCounter.Add(1)
	return fmt.Sprintf("file:authtest%d?mode=memory&cache=shared", n)
}

// setupEmbyServer creates a mock Emby API httptest.Server.
func setupEmbyServer(setup func(mux *http.ServeMux)) *httptest.Server {
	mux := http.NewServeMux()
	setup(mux)
	return httptest.NewServer(mux)
}

// nextHandler is a simple handler that records whether it was called and stores the auth token.
type nextHandler struct {
	called    bool
	authToken string
}

func (h *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.authToken = middleware.AuthTokenFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

// TestAuth_MissingSub verifies that a request without a sub claim returns 401.
func TestAuth_MissingSub(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	srv := setupEmbyServer(func(mux *http.ServeMux) {})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No sub header or JWT — should fail.
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
}

// TestAuth_MissingPreferredUsername verifies that a request with sub but no preferred_username returns 401.
func TestAuth_MissingPreferredUsername(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	srv := setupEmbyServer(func(mux *http.ServeMux) {})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-123")
	// No preferred_username.
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
}

// TestAuth_ExistingUserInDB verifies that a user already in the DB is authenticated with stored password.
func TestAuth_ExistingUserInDB(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	// Pre-insert user into DB.
	err = database.InsertUser("sub-alice", "user-123", "storedpw")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Username string `json:"Username"`
				Pw       string `json:"Pw"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)

			// Username should be the preferred_username "Alice".
			if body.Username != "Alice" {
				t.Errorf("expected username Alice, got %s", body.Username)
			}
			if body.Pw != "storedpw" {
				t.Errorf("expected password storedpw, got %s", body.Pw)
			}

			resp := map[string]interface{}{
				"AccessToken": "token-abc",
				"User":        map[string]interface{}{"Id": "user-123", "Name": "Alice"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/user-123/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/user-123", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id":   "user-123",
				"Name": "Alice",
				"Policy": map[string]interface{}{
					"IsDisabled":                 false,
					"IsHidden":                   true,
					"EnableUserPreferenceAccess": false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-alice")
	req.Header.Set("X-Forwarded-Preferred-Username", "Alice")
	req.Header.Set("X-Forwarded-User", "Alice")
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !next.called {
		t.Error("next handler should have been called")
	}
	if next.authToken != "token-abc" {
		t.Errorf("expected auth token %q, got %q", "token-abc", next.authToken)
	}
}

// TestAuth_ExistingUserPreferredUsernameMismatch verifies that auth fails with 409
// when OIDC preferred_username is already used by another Emby account.
func TestAuth_ExistingUserPreferredUsernameMismatch(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-admin", "admin-user-id", "storedpw")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{
					{"Id": "other-admin-id", "Name": "admin"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/admin-user-id", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id":   "admin-user-id",
				"Name": "admin@example.com",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-admin")
	req.Header.Set("X-Forwarded-Preferred-Username", "admin")
	req.Header.Set("X-Forwarded-User", "Admin User")
	req.Header.Set("X-Forwarded-Email", "admin@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d: %s", http.StatusConflict, rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "preferred_username is already used by Emby user other-admin-id") {
		t.Errorf("expected conflict message with blocking user id, got %q", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "linked account admin-user-id") {
		t.Errorf("expected conflict message with linked account id, got %q", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "admin@example.com") || strings.Contains(rr.Body.String(), "\"admin\"") {
		t.Errorf("conflict response must not contain personal data, got %q", rr.Body.String())
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
}

// TestAuth_NewUserProvisioning verifies the full provisioning flow for a brand new user.
// The Emby username should be the OIDC preferred_username claim.
func TestAuth_NewUserProvisioning(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	var createCalled bool
	var createdName string

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			createCalled = true
			var body struct {
				Name string `json:"Name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdName = body.Name

			resp := map[string]interface{}{
				"Id":   "new-user-456",
				"Name": body.Name,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/new-user-456/Password", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/new-user-456/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/new-user-456", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id":   "new-user-456",
				"Name": "New User",
				"Policy": map[string]interface{}{
					"IsDisabled":                 false,
					"IsHidden":                   true,
					"EnableUserPreferenceAccess": false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "new-token-xyz",
				"User":        map[string]interface{}{"Id": "new-user-456", "Name": "New User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-new")
	req.Header.Set("X-Forwarded-Preferred-Username", "newuser")
	req.Header.Set("X-Forwarded-User", "New User")
	req.Header.Set("X-Forwarded-Email", "newuser@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !next.called {
		t.Error("next handler should have been called")
	}
	if !createCalled {
		t.Error("CreateUser should have been called")
	}
	// Emby username should be preferred_username, not display name or email.
	if createdName != "newuser" {
		t.Errorf("expected Emby username %q, got %q", "newuser", createdName)
	}
	if next.authToken != "new-token-xyz" {
		t.Errorf("expected auth token %q, got %q", "new-token-xyz", next.authToken)
	}

	// Verify user was stored in DB with sub as key.
	record, err := database.FindUserBySub("sub-new")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
	if record.EmbyUserID != "new-user-456" {
		t.Errorf("expected emby_user_id %q, got %q", "new-user-456", record.EmbyUserID)
	}
}

// TestAuth_EmailNotUsedAsUsername verifies that email alone is rejected without preferred_username.
func TestAuth_EmailNotUsedAsUsername(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	srv := setupEmbyServer(func(mux *http.ServeMux) {})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-emailonly")
	req.Header.Set("X-Forwarded-Email", "emailonly@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
}

// TestAuth_AdoptedUser verifies the flow when a user exists in Emby but not in the DB.
func TestAuth_AdoptedUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	var passwordUpdateCalled bool

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{
					{"Id": "existing-emby-789", "Name": "Adopted User"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/existing-emby-789/Password", func(w http.ResponseWriter, r *http.Request) {
			passwordUpdateCalled = true
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/existing-emby-789/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/existing-emby-789", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id": "existing-emby-789", "Name": "Adopted User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "adopted-token",
				"User":        map[string]interface{}{"Id": "existing-emby-789", "Name": "Adopted User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-adopted")
	req.Header.Set("X-Forwarded-Preferred-Username", "Adopted User")
	req.Header.Set("X-Forwarded-User", "Adopted User")
	req.Header.Set("X-Forwarded-Email", "adopted@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !next.called {
		t.Error("next handler should have been called")
	}
	if !passwordUpdateCalled {
		t.Error("UpdatePassword should have been called for adopted user")
	}
	if next.authToken != "adopted-token" {
		t.Errorf("expected auth token %q, got %q", "adopted-token", next.authToken)
	}

	// Verify user was stored in DB with sub as key.
	record, err := database.FindUserBySub("sub-adopted")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
	if record.EmbyUserID != "existing-emby-789" {
		t.Errorf("expected emby_user_id %q, got %q", "existing-emby-789", record.EmbyUserID)
	}
}

// TestAuth_EmbyUnreachable verifies that a 503 is returned when Emby API is unreachable.
func TestAuth_EmbyUnreachable(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-unreachable")
	req.Header.Set("X-Forwarded-Preferred-Username", "unreachable")
	req.Header.Set("X-Forwarded-Email", "unreachable@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rr.Code)
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
}

// TestAuth_UserCreationFailure verifies that a 500 is returned when user creation fails.
func TestAuth_UserCreationFailure(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-failcreate")
	req.Header.Set("X-Forwarded-Preferred-Username", "failcreate")
	req.Header.Set("X-Forwarded-Email", "failcreate@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
}

// TestAuth_AuthTokenInContext verifies that the auth token is stored in context.
func TestAuth_AuthTokenInContext(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-ctx", "user-ctx", "ctxpass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "context-token-value",
				"User":        map[string]interface{}{"Id": "user-ctx", "Name": "Context User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/user-ctx/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/user-ctx", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id": "user-ctx", "Name": "Context User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")

	var capturedToken string
	nextFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedToken = middleware.AuthTokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(nextFn)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-ctx")
	req.Header.Set("X-Forwarded-Preferred-Username", "Context User")
	req.Header.Set("X-Forwarded-User", "Context User")
	req.Header.Set("X-Forwarded-Email", "context@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if capturedToken != "context-token-value" {
		t.Errorf("expected context token %q, got %q", "context-token-value", capturedToken)
	}
}

// TestAuth_SubFromJWT verifies that sub is extracted from the JWT when no header is present.
func TestAuth_SubFromJWT(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Id": "jwt-user-1", "Name": "jwtuser"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/jwt-user-1/Password", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/jwt-user-1/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/jwt-user-1", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id": "jwt-user-1", "Name": "jwtuser",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "jwt-token",
				"User":        map[string]interface{}{"Id": "jwt-user-1", "Name": "jwtuser"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	// Build a JWT with sub and preferred_username claims.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"jwt-sub-001","preferred_username":"jwtuser","email":"jwt@example.com"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jwtToken := header + "." + payload + "." + signature

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No X-Forwarded-Sub — sub should come from JWT.
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !next.called {
		t.Error("next handler should have been called")
	}

	// Verify user was stored with JWT sub.
	record, err := database.FindUserBySub("jwt-sub-001")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
}

// TestAuth_UsernameSync verifies that username changes in OIDC are synced to Emby.
func TestAuth_UsernameSync(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	// Insert user with old name.
	err = database.InsertUser("sub-rename", "emby-rename-1", "renamepass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	var renameCalled bool
	var newNameSent string

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		// POST /Users/{id} — rename user.
		mux.HandleFunc("POST /Users/emby-rename-1", func(w http.ResponseWriter, r *http.Request) {
			renameCalled = true
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			newNameSent = body["Name"]
			w.WriteHeader(http.StatusOK)
		})
		// GET /Users/{id} — get user policy.
		mux.HandleFunc("GET /Users/emby-rename-1", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id": "emby-rename-1", "Name": "Old Name",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/emby-rename-1/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "rename-token",
				"User":        map[string]interface{}{"Id": "emby-rename-1", "Name": "New Name"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-rename")
	req.Header.Set("X-Forwarded-Preferred-Username", "New Name")
	req.Header.Set("X-Forwarded-User", "New Name")
	req.Header.Set("X-Forwarded-Email", "user@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !renameCalled {
		t.Error("UpdateUserName should have been called to sync name change")
	}
	if newNameSent != "New Name" {
		t.Errorf("expected new name %q, got %q", "New Name", newNameSent)
	}
}

// TestAuth_AdminManualEmbyRename verifies that an admin rename in Emby does not
// trigger re-provisioning. The linked account is found by ID, renamed back to
// OIDC preferred_username, and the session cache is invalidated on drift.
func TestAuth_AdminManualEmbyRename(t *testing.T) {
	middleware.ClearSessionCache()

	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	const (
		oidcSub       = "sub-admin-rename"
		preferredName = "alice"
		adminRenamed  = "bob"
		embyUserID    = "emby-alice-1"
		storedPass    = "storedpw"
	)

	err = database.InsertUser(oidcSub, embyUserID, storedPass)
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	var (
		embyNameMu          sync.Mutex
		embyName            = preferredName
		renameCalled        bool
		renameTarget        string
		createCalled        bool
		passwordUpdateCount int32
		authCount           int32
	)

	setEmbyName := func(name string) {
		embyNameMu.Lock()
		embyName = name
		embyNameMu.Unlock()
	}
	getEmbyName := func() string {
		embyNameMu.Lock()
		defer embyNameMu.Unlock()
		return embyName
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("GET /Users/"+embyUserID, func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id":   embyUserID,
				"Name": getEmbyName(),
				"Policy": map[string]interface{}{
					"IsDisabled":                 false,
					"IsHidden":                   true,
					"EnableUserPreferenceAccess": false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("POST /Users/"+embyUserID, func(w http.ResponseWriter, r *http.Request) {
			renameCalled = true
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			renameTarget = body["Name"]
			setEmbyName(body["Name"])
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/Users/"+embyUserID+"/Password", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&passwordUpdateCount, 1)
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			createCalled = true
			w.WriteHeader(http.StatusInternalServerError)
		})
		mux.HandleFunc("/Users/"+embyUserID+"/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&authCount, 1)
			var body struct {
				Username string `json:"Username"`
				Pw       string `json:"Pw"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)

			if body.Username != preferredName {
				t.Errorf("expected auth username %q, got %q", preferredName, body.Username)
			}
			if body.Pw != storedPass {
				t.Errorf("expected stored password, got %q", body.Pw)
			}

			resp := map[string]interface{}{
				"AccessToken": "rename-token",
				"User":        map[string]interface{}{"Id": embyUserID, "Name": preferredName},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-Sub", oidcSub)
		req.Header.Set("X-Forwarded-Preferred-Username", preferredName)
		req.Header.Set("X-Forwarded-User", preferredName)
		req.Header.Set("X-Forwarded-Email", "alice@example.com")
		return req
	}

	// First request: populate session cache with matching username.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, makeReq())
	if rr.Code != http.StatusOK {
		t.Fatalf("first request: expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if atomic.LoadInt32(&authCount) != 1 {
		t.Fatalf("first request: expected 1 auth call, got %d", authCount)
	}

	// Simulate admin manual rename in Emby.
	setEmbyName(adminRenamed)
	renameCalled = false

	// Second request: cache drift should force full auth, rename back, no re-provision.
	next = &nextHandler{}
	handler = middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, makeReq())

	if rr.Code != http.StatusOK {
		t.Fatalf("second request: expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !next.called {
		t.Fatal("second request: next handler should have been called")
	}
	if !renameCalled {
		t.Error("expected Emby username reset after admin rename")
	}
	if renameTarget != preferredName {
		t.Errorf("expected rename target %q, got %q", preferredName, renameTarget)
	}
	if createCalled {
		t.Error("CreateUser should not be called for admin rename")
	}
	if atomic.LoadInt32(&passwordUpdateCount) != 0 {
		t.Errorf("expected no password updates during rename recovery, got %d", passwordUpdateCount)
	}
	if atomic.LoadInt32(&authCount) != 2 {
		t.Errorf("expected 2 auth calls (cache invalidated), got %d", authCount)
	}

	record, err := database.FindUserBySub(oidcSub)
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record to remain in db")
	}
	if record.EmbyUserID != embyUserID {
		t.Errorf("expected emby_user_id %q unchanged, got %q", embyUserID, record.EmbyUserID)
	}
	if record.Password != storedPass {
		t.Errorf("expected password unchanged, got %q", record.Password)
	}
}

// TestExtractPictureFromJWT_ValidToken verifies picture extraction from a valid JWT payload.
func TestExtractPictureFromJWT_ValidToken(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user123","picture":"https://example.com/photo.jpg","email":"user@example.com"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesignature"))
	token := header + "." + payload + "." + signature

	got := middleware.ExtractPictureFromJWT(token)
	if got != "https://example.com/photo.jpg" {
		t.Errorf("ExtractPictureFromJWT = %q, want %q", got, "https://example.com/photo.jpg")
	}
}

// TestExtractPictureFromJWT_NoPictureClaim verifies empty string when picture claim is absent.
func TestExtractPictureFromJWT_NoPictureClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user123","email":"user@example.com"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesignature"))
	token := header + "." + payload + "." + signature

	got := middleware.ExtractPictureFromJWT(token)
	if got != "" {
		t.Errorf("ExtractPictureFromJWT = %q, want empty string", got)
	}
}

// TestExtractPictureFromJWT_InvalidToken verifies empty string for malformed tokens.
func TestExtractPictureFromJWT_InvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"no dots", "nodots"},
		{"one dot", "one.dot"},
		{"invalid base64 payload", "header.!!!invalid!!!.signature"},
		{"invalid JSON payload", "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := middleware.ExtractPictureFromJWT(tt.token)
			if got != "" {
				t.Errorf("ExtractPictureFromJWT(%q) = %q, want empty string", tt.token, got)
			}
		})
	}
}

// TestExtractPictureFromJWT_PaddingVariants verifies base64 padding handling.
func TestExtractPictureFromJWT_PaddingVariants(t *testing.T) {
	tests := []struct {
		name    string
		claims  map[string]string
		wantPic string
	}{
		{
			name:    "short URL",
			claims:  map[string]string{"picture": "https://a.co/p"},
			wantPic: "https://a.co/p",
		},
		{
			name:    "longer URL",
			claims:  map[string]string{"picture": "https://example.com/users/12345/avatar.png"},
			wantPic: "https://example.com/users/12345/avatar.png",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadJSON, _ := json.Marshal(tt.claims)
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
			payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
			token := header + "." + payload + ".sig"

			got := middleware.ExtractPictureFromJWT(token)
			if got != tt.wantPic {
				t.Errorf("ExtractPictureFromJWT = %q, want %q", got, tt.wantPic)
			}
		})
	}
}

// TestBuildUserPolicy_OverridesFields verifies that buildUserPolicy sets IsDisabled=false
// and EnableUserPreferenceAccess=false while preserving other fields.
func TestBuildUserPolicy_OverridesFields(t *testing.T) {
	templatePolicy := []byte(`{
		"IsDisabled": true,
		"IsHidden": true,
		"EnableUserPreferenceAccess": true,
		"MaxParentalRating": 10,
		"BlockedTags": ["adult"]
	}`)

	result, err := middleware.BuildUserPolicy(templatePolicy)
	if err != nil {
		t.Fatalf("BuildUserPolicy failed: %v", err)
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(result, &policy); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if isDisabled, ok := policy["IsDisabled"].(bool); !ok || isDisabled {
		t.Errorf("IsDisabled = %v, want false", policy["IsDisabled"])
	}
	if prefAccess, ok := policy["EnableUserPreferenceAccess"].(bool); !ok || prefAccess {
		t.Errorf("EnableUserPreferenceAccess = %v, want false", policy["EnableUserPreferenceAccess"])
	}
	if isHidden, ok := policy["IsHidden"].(bool); !ok || !isHidden {
		t.Errorf("IsHidden = %v, want true (preserved from template)", policy["IsHidden"])
	}
	if rating, ok := policy["MaxParentalRating"].(float64); !ok || rating != 10 {
		t.Errorf("MaxParentalRating = %v, want 10", policy["MaxParentalRating"])
	}
}

// TestBuildUserPolicy_InvalidJSON verifies error handling for invalid JSON input.
func TestBuildUserPolicy_InvalidJSON(t *testing.T) {
	_, err := middleware.BuildUserPolicy([]byte("not valid json"))
	if err == nil {
		t.Error("BuildUserPolicy should return error for invalid JSON")
	}
}

// TestAuth_PreferredUsernameOverName verifies that preferred_username is used over name.
func TestAuth_PreferredUsernameOverName(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	var createdName string

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			var body struct{ Name string `json:"Name"` }
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdName = body.Name
			resp := map[string]interface{}{"Id": "pref-user-1", "Name": body.Name}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/pref-user-1/Password", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/pref-user-1/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/Users/pref-user-1", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Id": "pref-user-1", "Name": "johndoe",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "pref-token",
				"User":        map[string]interface{}{"Id": "pref-user-1", "Name": "johndoe"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	// Build JWT with both preferred_username and name.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"sub-pref","preferred_username":"johndoe","name":"John Doe","email":"john@example.com"}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	jwtToken := header + "." + payload + "." + signature

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	// Emby username should be preferred_username, not name.
	if createdName != "johndoe" {
		t.Errorf("expected Emby username %q (preferred_username), got %q", "johndoe", createdName)
	}
}

// TestAuth_UsernameCreationConflict verifies that user creation fails when the preferred username is taken.
func TestAuth_UsernameCreationConflict(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	var createdNames []string

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			var body struct{ Name string `json:"Name"` }
			_ = json.NewDecoder(r.Body).Decode(&body)
			createdNames = append(createdNames, body.Name)
			w.WriteHeader(http.StatusBadRequest)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-conflict")
	req.Header.Set("X-Forwarded-Preferred-Username", "johndoe")
	req.Header.Set("X-Forwarded-User", "John Doe")
	req.Header.Set("X-Forwarded-Email", "john@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
	if next.called {
		t.Error("next handler should not have been called")
	}
	if len(createdNames) != 1 {
		t.Fatalf("expected 1 creation attempt, got %d: %v", len(createdNames), createdNames)
	}
	if createdNames[0] != "johndoe" {
		t.Errorf("creation attempt should be 'johndoe', got %q", createdNames[0])
	}
}

// TestAuth_PolicyUpdateSkippedWhenAlreadyCorrect verifies that the background policy
// enforcement goroutine does NOT call UpdatePolicyRaw when IsDisabled is already false
// and EnableUserPreferenceAccess is already false.
func TestAuth_PolicyUpdateSkippedWhenAlreadyCorrect(t *testing.T) {
	middleware.ClearSessionCache()

	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-policy-skip", "policy-skip-1", "skippass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	policyUpdateCalled := make(chan struct{}, 1)
	policyGetDone := make(chan struct{})

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "skip-token",
				"User":        map[string]interface{}{"Id": "policy-skip-1", "Name": "PolicySkip"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("GET /Users/policy-skip-1", func(w http.ResponseWriter, r *http.Request) {
			defer close(policyGetDone)
			// Policy already has the desired values — no update needed.
			resp := map[string]interface{}{
				"Id":   "policy-skip-1",
				"Name": "PolicySkip",
				"Policy": map[string]interface{}{
					"IsDisabled":                 false,
					"IsHidden":                   true,
					"EnableUserPreferenceAccess": false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("POST /Users/policy-skip-1/Policy", func(w http.ResponseWriter, r *http.Request) {
			policyUpdateCalled <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-policy-skip")
	req.Header.Set("X-Forwarded-Preferred-Username", "PolicySkip")
	req.Header.Set("X-Forwarded-User", "PolicySkip")
	req.Header.Set("X-Forwarded-Email", "policyskip@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Wait for the background goroutine to complete its GET request.
	<-policyGetDone

	// The policy POST should NOT have been called since values are already correct.
	select {
	case <-policyUpdateCalled:
		t.Error("UpdatePolicyRaw should NOT have been called when policy already matches desired state")
	default:
		// Expected: no update called.
	}
}

// TestAuth_PolicyUpdateCalledWhenDisabled verifies that the background policy
// enforcement goroutine DOES call UpdatePolicyRaw when IsDisabled is true.
func TestAuth_PolicyUpdateCalledWhenDisabled(t *testing.T) {
	middleware.ClearSessionCache()

	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-policy-disabled", "policy-disabled-1", "disabledpass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	policyUpdateCalled := make(chan struct{}, 1)

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "disabled-token",
				"User":        map[string]interface{}{"Id": "policy-disabled-1", "Name": "PolicyDisabled"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("GET /Users/policy-disabled-1", func(w http.ResponseWriter, r *http.Request) {
			// User is disabled — policy update should be triggered.
			resp := map[string]interface{}{
				"Id":   "policy-disabled-1",
				"Name": "PolicyDisabled",
				"Policy": map[string]interface{}{
					"IsDisabled":                 true,
					"IsHidden":                   true,
					"EnableUserPreferenceAccess": false,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("POST /Users/policy-disabled-1/Policy", func(w http.ResponseWriter, r *http.Request) {
			// Verify the policy being set has IsDisabled=false.
			var policy map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&policy)
			if isDisabled, ok := policy["IsDisabled"].(bool); ok && isDisabled {
				t.Error("expected IsDisabled=false in policy update")
			}
			policyUpdateCalled <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-policy-disabled")
	req.Header.Set("X-Forwarded-Preferred-Username", "PolicyDisabled")
	req.Header.Set("X-Forwarded-User", "PolicyDisabled")
	req.Header.Set("X-Forwarded-Email", "policydisabled@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Wait for the background goroutine to call the policy update endpoint.
	timeout := time.After(5 * time.Second)
	select {
	case <-policyUpdateCalled:
		// Expected: policy update was called because IsDisabled was true.
	case <-timeout:
		t.Fatal("timed out waiting for policy update call")
	}
}

// TestAuth_PolicyUpdateCalledWhenPrefAccessEnabled verifies that the background policy
// enforcement goroutine DOES call UpdatePolicyRaw when EnableUserPreferenceAccess is true.
func TestAuth_PolicyUpdateCalledWhenPrefAccessEnabled(t *testing.T) {
	middleware.ClearSessionCache()

	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-policy-pref", "policy-pref-1", "prefpass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	policyUpdateCalled := make(chan struct{}, 1)

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "pref-token",
				"User":        map[string]interface{}{"Id": "policy-pref-1", "Name": "PolicyPref"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("GET /Users/policy-pref-1", func(w http.ResponseWriter, r *http.Request) {
			// EnableUserPreferenceAccess is true — policy update should be triggered.
			resp := map[string]interface{}{
				"Id":   "policy-pref-1",
				"Name": "PolicyPref",
				"Policy": map[string]interface{}{
					"IsDisabled":                 false,
					"IsHidden":                   true,
					"EnableUserPreferenceAccess": true,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("POST /Users/policy-pref-1/Policy", func(w http.ResponseWriter, r *http.Request) {
			// Verify the policy being set has EnableUserPreferenceAccess=false.
			var policy map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&policy)
			if prefAccess, ok := policy["EnableUserPreferenceAccess"].(bool); ok && prefAccess {
				t.Error("expected EnableUserPreferenceAccess=false in policy update")
			}
			policyUpdateCalled <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Sub", "sub-policy-pref")
	req.Header.Set("X-Forwarded-Preferred-Username", "PolicyPref")
	req.Header.Set("X-Forwarded-User", "PolicyPref")
	req.Header.Set("X-Forwarded-Email", "policypref@example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Wait for the background goroutine to call the policy update endpoint.
	timeout := time.After(5 * time.Second)
	select {
	case <-policyUpdateCalled:
		// Expected: policy update was called because EnableUserPreferenceAccess was true.
	case <-timeout:
		t.Fatal("timed out waiting for policy update call")
	}
}
