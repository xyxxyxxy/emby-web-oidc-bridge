package middleware_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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

// embyMux creates a mock Emby API server with configurable behavior.
type embyMux struct {
	mux *http.ServeMux
}

func newEmbyMux() *embyMux {
	return &embyMux{mux: http.NewServeMux()}
}

func (e *embyMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mux.ServeHTTP(w, r)
}

// setupEmbyServer creates a mock Emby API httptest.Server.
// The handler function receives the mux to register routes.
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

// TestAuth_MissingEmail verifies that a request without X-Forwarded-Email returns 401.
// Validates: Requirements 1.4
func TestAuth_MissingEmail(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		// No routes needed — should not be called.
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No X-Forwarded-Email header set.
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
// Validates: Requirements 3.5, 7.4
func TestAuth_ExistingUserInDB(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Pre-insert user into DB.
	err = database.InsertUser("alice@example.com", "user-123", "storedpw")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				Username string `json:"Username"`
				Pw       string `json:"Pw"`
			}
			json.NewDecoder(r.Body).Decode(&body)

			if body.Username != "alice@example.com" {
				t.Errorf("expected username alice@example.com, got %s", body.Username)
			}
			if body.Pw != "storedpw" {
				t.Errorf("expected password storedpw, got %s", body.Pw)
			}

			resp := map[string]interface{}{
				"AccessToken": "token-abc",
				"User":        map[string]interface{}{"Id": "user-123", "Name": "alice@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		// Policy update (non-blocking goroutine).
		mux.HandleFunc("/Users/user-123/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

// TestAuth_NewUserProvisioning verifies the full provisioning flow for a brand new user.
// Validates: Requirements 1.3, 2.4, 3.5
func TestAuth_NewUserProvisioning(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	var (
		createCalled   bool
		passwordCalled bool
		policyCalled   bool
	)

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		// FindUserByName — user not found.
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		// CreateUser.
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			createCalled = true
			var body struct {
				Name            string   `json:"Name"`
				CopyFromUserID  string   `json:"CopyFromUserId"`
				UserCopyOptions []string `json:"UserCopyOptions"`
			}
			json.NewDecoder(r.Body).Decode(&body)

			if body.Name != "newuser@example.com" {
				t.Errorf("expected Name newuser@example.com, got %s", body.Name)
			}
			if body.CopyFromUserID != "template-user-id" {
				t.Errorf("expected CopyFromUserId template-user-id, got %s", body.CopyFromUserID)
			}

			resp := map[string]interface{}{
				"Id":   "new-user-456",
				"Name": "newuser@example.com",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		// UpdatePassword.
		mux.HandleFunc("/Users/new-user-456/Password", func(w http.ResponseWriter, r *http.Request) {
			passwordCalled = true
			w.WriteHeader(http.StatusNoContent)
		})
		// UpdatePolicy.
		mux.HandleFunc("/Users/new-user-456/Policy", func(w http.ResponseWriter, r *http.Request) {
			policyCalled = true
			w.WriteHeader(http.StatusNoContent)
		})
		// AuthenticateByName.
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "new-token-xyz",
				"User":        map[string]interface{}{"Id": "new-user-456", "Name": "newuser@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	if !passwordCalled {
		t.Error("UpdatePassword should have been called")
	}
	if !policyCalled {
		t.Error("UpdatePolicy should have been called")
	}
	if next.authToken != "new-token-xyz" {
		t.Errorf("expected auth token %q, got %q", "new-token-xyz", next.authToken)
	}

	// Verify user was stored in DB.
	record, err := database.FindUser("newuser@example.com")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
	if record.EmbyUserID != "new-user-456" {
		t.Errorf("expected emby_user_id %q, got %q", "new-user-456", record.EmbyUserID)
	}
	if record.Password == "" {
		t.Error("expected non-empty password in db")
	}
}

// TestAuth_AdoptedUser verifies the flow when a user exists in Emby but not in the DB.
// Validates: Requirements 7.5
func TestAuth_AdoptedUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	var passwordUpdateCalled bool

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		// FindUserByName — user exists in Emby.
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{
					{"Id": "existing-emby-789", "Name": "adopted@example.com"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		// UpdatePassword — should be called to set new password.
		mux.HandleFunc("/Users/existing-emby-789/Password", func(w http.ResponseWriter, r *http.Request) {
			passwordUpdateCalled = true
			w.WriteHeader(http.StatusNoContent)
		})
		// Policy update (non-blocking goroutine).
		mux.HandleFunc("/Users/existing-emby-789/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		// AuthenticateByName.
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "adopted-token",
				"User":        map[string]interface{}{"Id": "existing-emby-789", "Name": "adopted@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

	// Verify user was stored in DB.
	record, err := database.FindUser("adopted@example.com")
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
// Validates: Requirements 2.4, 7.4
func TestAuth_EmbyUnreachable(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Use a closed server to simulate unreachable Emby.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // Close immediately to make it unreachable.

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
// Validates: Requirements 3.5
func TestAuth_UserCreationFailure(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		// FindUserByName — user not found.
		mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		// CreateUser — fails with 500.
		mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

// TestAuth_AuthTokenInContext verifies that the auth token is stored in context for downstream handlers.
// Validates: Requirements 7.4
func TestAuth_AuthTokenInContext(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Pre-insert user.
	err = database.InsertUser("context@example.com", "user-ctx", "ctxpass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "context-token-value",
				"User":        map[string]interface{}{"Id": "user-ctx", "Name": "context@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/user-ctx/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
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

// TestAuth_MissingOptionalHeaders verifies that missing optional headers don't cause failures.
// Validates: Requirements 1.3
func TestAuth_MissingOptionalHeaders(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Pre-insert user.
	err = database.InsertUser("nooptional@example.com", "user-opt", "optpass")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	srv := setupEmbyServer(func(mux *http.ServeMux) {
		mux.HandleFunc("/Users/AuthenticateByName", func(w http.ResponseWriter, r *http.Request) {
			resp := map[string]interface{}{
				"AccessToken": "opt-token",
				"User":        map[string]interface{}{"Id": "user-opt", "Name": "nooptional@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		})
		mux.HandleFunc("/Users/user-opt/Policy", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
	defer srv.Close()

	client := emby.NewClient(srv.URL, "test-key")
	next := &nextHandler{}
	handler := middleware.Auth(client, database, "template-user-id", testTemplatePolicy, "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Email", "nooptional@example.com")
	// No X-Forwarded-User or X-Forwarded-Picture headers.
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if !next.called {
		t.Error("next handler should have been called")
	}
}
