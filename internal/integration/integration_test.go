package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/middleware"
)

var flowDBCounter atomic.Int64

// flowDBURI returns a unique in-memory database URI for each test.
func flowDBURI() string {
	n := flowDBCounter.Add(1)
	return fmt.Sprintf("file:flow%d?mode=memory&cache=shared", n)
}

// apiCall records a single API call made to the mock Emby server.
type apiCall struct {
	Method string
	Path   string
}

// buildFullChain constructs the full middleware chain: TrustedProxy → Auth → Proxy.
func buildFullChain(trustedCIDRs []*net.IPNet, embyClient *emby.Client, database *db.DB, templateUserID string, backendURL string) http.Handler {
	templatePolicy := []byte(`{"IsDisabled":true,"IsHidden":true,"EnableUserPreferenceAccess":true}`)
	proxyHandler := handler.Proxy(backendURL)
	authMiddleware := middleware.Auth(embyClient, database, templateUserID, templatePolicy)
	trustedProxyMiddleware := middleware.TrustedProxy(trustedCIDRs)

	return trustedProxyMiddleware(authMiddleware(proxyHandler))
}

// parseTrustedCIDRs parses a CIDR string into a []*net.IPNet slice.
func parseTrustedCIDRs(cidr string) []*net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR in test: %s", cidr))
	}
	return []*net.IPNet{network}
}

// TestIntegration_NewUserProvisioningFlow tests the complete provisioning flow:
// request → trusted proxy check → header extraction → user creation → auth → proxy
// Validates: Requirements 1.2, 1.3, 2.1, 2.3, 3.1, 3.2, 3.3, 3.4, 7.1, 7.2, 7.3
func TestIntegration_NewUserProvisioningFlow(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	var mu sync.Mutex
	var calls []apiCall

	// Mock Emby API server that tracks call order.
	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, apiCall{Method: r.Method, Path: r.URL.Path})
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/Users/Query":
			// User not found in Emby.
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/New":
			// Verify request body.
			var body struct {
				Name            string   `json:"Name"`
				CopyFromUserID  string   `json:"CopyFromUserId"`
				UserCopyOptions []string `json:"UserCopyOptions"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Name != "newuser@example.com" {
				t.Errorf("CreateUser: expected Name 'newuser@example.com', got %q", body.Name)
			}
			if body.CopyFromUserID != "template-id-001" {
				t.Errorf("CreateUser: expected CopyFromUserId 'template-id-001', got %q", body.CopyFromUserID)
			}

			resp := map[string]interface{}{
				"Id":   "created-user-001",
				"Name": "newuser@example.com",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/created-user-001/Password":
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/created-user-001/Policy":
			// Verify policy body.
			var body struct {
				IsDisabled                 bool `json:"IsDisabled"`
				EnableUserPreferenceAccess bool `json:"EnableUserPreferenceAccess"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.IsDisabled {
				t.Error("Policy: expected IsDisabled=false")
			}
			if body.EnableUserPreferenceAccess {
				t.Error("Policy: expected EnableUserPreferenceAccess=false")
			}
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "new-user-token-xyz",
				"User":        map[string]interface{}{"Id": "created-user-001", "Name": "newuser@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer embySrv.Close()

	// Backend server that the proxy forwards to — verifies the auth token is forwarded.
	var receivedToken string
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Emby-Token")
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend OK"))
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")

	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Items/123", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Email", "newuser@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	// Verify response was proxied successfully.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "backend OK" {
		t.Errorf("expected body 'backend OK', got %q", rec.Body.String())
	}

	// Verify auth token was forwarded to backend.
	if receivedToken != "new-user-token-xyz" {
		t.Errorf("expected X-Emby-Token 'new-user-token-xyz', got %q", receivedToken)
	}

	// Verify request path was preserved.
	if receivedPath != "/Items/123" {
		t.Errorf("expected path '/Items/123', got %q", receivedPath)
	}

	// Verify correct Emby API calls were made in order.
	// Note: non-blocking goroutine calls (policy update) may appear after the main flow.
	mu.Lock()
	mainCalls := make([]apiCall, len(calls))
	copy(mainCalls, calls)
	mu.Unlock()

	expectedOrder := []apiCall{
		{Method: http.MethodGet, Path: "/Users/Query"},
		{Method: http.MethodPost, Path: "/Users/New"},
		{Method: http.MethodPost, Path: "/Users/created-user-001/Password"},
		{Method: http.MethodPost, Path: "/Users/created-user-001/Password"},
		{Method: http.MethodPost, Path: "/Users/created-user-001/Policy"},
		{Method: http.MethodPost, Path: "/Users/AuthenticateByName"},
	}

	// Check that the first 5 calls match the expected synchronous order.
	if len(mainCalls) < len(expectedOrder) {
		t.Fatalf("expected at least %d API calls, got %d: %+v", len(expectedOrder), len(mainCalls), mainCalls)
	}
	for i, expected := range expectedOrder {
		if mainCalls[i].Method != expected.Method || mainCalls[i].Path != expected.Path {
			t.Errorf("call[%d]: expected %s %s, got %s %s", i, expected.Method, expected.Path, mainCalls[i].Method, mainCalls[i].Path)
		}
	}

	// Verify user was stored in the database.
	record, err := database.FindUser("newuser@example.com")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
	if record.EmbyUserID != "created-user-001" {
		t.Errorf("expected emby_user_id 'created-user-001', got %q", record.EmbyUserID)
	}
	if record.Password == "" {
		t.Error("expected non-empty password in db")
	}
}

// TestIntegration_ExistingUserLoginFlow tests the login flow for a user already in the DB:
// request → trusted proxy check → header extraction → authenticate with stored password → proxy
// Validates: Requirements 1.2, 1.3, 2.2, 3.4, 7.1, 7.2, 7.3
func TestIntegration_ExistingUserLoginFlow(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Pre-insert user into DB.
	err = database.InsertUser("existing@example.com", "emby-user-100", "mypassw1")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	var mu sync.Mutex
	var calls []apiCall
	var authPassword string

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, apiCall{Method: r.Method, Path: r.URL.Path})
		mu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			var body struct {
				Username string `json:"Username"`
				Pw       string `json:"Pw"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			authPassword = body.Pw

			if body.Username != "existing@example.com" {
				t.Errorf("expected username 'existing@example.com', got %q", body.Username)
			}

			resp := map[string]interface{}{
				"AccessToken": "existing-token-abc",
				"User":        map[string]interface{}{"Id": "emby-user-100", "Name": "existing@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/emby-user-100/Policy":
			// Non-blocking policy update.
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer embySrv.Close()

	var receivedToken string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Emby-Token")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")

	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/web/index.html", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-Email", "existing@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "proxied" {
		t.Errorf("expected body 'proxied', got %q", rec.Body.String())
	}

	// Verify stored password was used for authentication.
	if authPassword != "mypassw1" {
		t.Errorf("expected auth password 'mypassw1', got %q", authPassword)
	}

	// Verify auth token was forwarded to backend.
	if receivedToken != "existing-token-abc" {
		t.Errorf("expected X-Emby-Token 'existing-token-abc', got %q", receivedToken)
	}

	// Verify no user creation calls were made (only AuthenticateByName + async policy).
	mu.Lock()
	syncCalls := make([]apiCall, len(calls))
	copy(syncCalls, calls)
	mu.Unlock()

	if len(syncCalls) < 1 {
		t.Fatal("expected at least 1 API call")
	}
	if syncCalls[0].Method != http.MethodPost || syncCalls[0].Path != "/Users/AuthenticateByName" {
		t.Errorf("first call should be POST /Users/AuthenticateByName, got %s %s", syncCalls[0].Method, syncCalls[0].Path)
	}
}

// TestIntegration_AdoptedUserFlow tests the flow when a user exists in Emby but not in the DB:
// request → trusted proxy check → header extraction → find in Emby → generate password → update password → store in DB → auth → proxy
// Validates: Requirements 1.2, 1.3, 2.1, 2.2, 7.1, 7.2, 7.3, 7.6
func TestIntegration_AdoptedUserFlow(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	var mu sync.Mutex
	var calls []apiCall

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, apiCall{Method: r.Method, Path: r.URL.Path})
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/Users/Query":
			// User exists in Emby.
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{
					{"Id": "adopted-emby-555", "Name": "adopted@example.com"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/adopted-emby-555/Password":
			// Password update for adopted user.
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/adopted-emby-555/Policy":
			// Non-blocking policy update.
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "adopted-token-999",
				"User":        map[string]interface{}{"Id": "adopted-emby-555", "Name": "adopted@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		default:
			t.Errorf("unexpected API call: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer embySrv.Close()

	var receivedToken string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Emby-Token")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("adopted OK"))
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")

	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Library", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-Email", "adopted@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "adopted OK" {
		t.Errorf("expected body 'adopted OK', got %q", rec.Body.String())
	}

	// Verify auth token was forwarded.
	if receivedToken != "adopted-token-999" {
		t.Errorf("expected X-Emby-Token 'adopted-token-999', got %q", receivedToken)
	}

	// Verify correct API call order for adopted user flow.
	mu.Lock()
	syncCalls := make([]apiCall, len(calls))
	copy(syncCalls, calls)
	mu.Unlock()

	expectedOrder := []apiCall{
		{Method: http.MethodGet, Path: "/Users/Query"},
		{Method: http.MethodPost, Path: "/Users/adopted-emby-555/Password"},
		{Method: http.MethodPost, Path: "/Users/adopted-emby-555/Password"},
		{Method: http.MethodPost, Path: "/Users/AuthenticateByName"},
	}

	if len(syncCalls) < len(expectedOrder) {
		t.Fatalf("expected at least %d API calls, got %d: %+v", len(expectedOrder), len(syncCalls), syncCalls)
	}
	for i, expected := range expectedOrder {
		if syncCalls[i].Method != expected.Method || syncCalls[i].Path != expected.Path {
			t.Errorf("call[%d]: expected %s %s, got %s %s", i, expected.Method, expected.Path, syncCalls[i].Method, syncCalls[i].Path)
		}
	}

	// Verify NO CreateUser call was made (user already exists in Emby).
	for _, c := range syncCalls {
		if c.Path == "/Users/New" {
			t.Error("CreateUser should NOT have been called for adopted user")
		}
	}

	// Verify user was stored in the database.
	record, err := database.FindUser("adopted@example.com")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
	if record.EmbyUserID != "adopted-emby-555" {
		t.Errorf("expected emby_user_id 'adopted-emby-555', got %q", record.EmbyUserID)
	}
	if record.Password == "" {
		t.Error("expected non-empty password in db")
	}
}

// TestIntegration_RequestBodyPreserved verifies that request body is preserved through the full chain.
// Validates: Requirements 7.3
func TestIntegration_RequestBodyPreserved(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Pre-insert user.
	err = database.InsertUser("body@example.com", "emby-body-user", "bodypass1")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "body-token",
				"User":        map[string]interface{}{"Id": "emby-body-user", "Name": "body@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/Users/emby-body-user/Policy":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer embySrv.Close()

	var receivedBody string
	var receivedContentType string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")

	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	bodyContent := `{"query":"search term","limit":10}`
	req := httptest.NewRequest(http.MethodPost, "/Items/Query", strings.NewReader(bodyContent))
	req.RemoteAddr = "127.0.0.1:11111"
	req.Header.Set("X-Forwarded-Email", "body@example.com")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if receivedBody != bodyContent {
		t.Errorf("expected body %q, got %q", bodyContent, receivedBody)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}
}

// TestIntegration_AuthTokenForwardedToProxy verifies that the auth token set by the auth middleware
// is correctly forwarded by the proxy handler as X-Emby-Token header.
// This specifically tests the context key sharing between middleware and handler packages.
// Validates: Requirements 7.2
func TestIntegration_AuthTokenForwardedToProxy(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer database.Close()

	// Pre-insert user.
	err = database.InsertUser("token@example.com", "emby-token-user", "tokenpw1")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "forwarded-token-value",
				"User":        map[string]interface{}{"Id": "emby-token-user", "Name": "token@example.com"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/Users/emby-token-user/Policy":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer embySrv.Close()

	var receivedToken string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Emby-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")

	// Use the real proxy handler (not a mock) to verify token forwarding end-to-end.
	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	req.RemoteAddr = "127.0.0.1:22222"
	req.Header.Set("X-Forwarded-Email", "token@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// This is the critical assertion: the auth token from the middleware
	// must be readable by the proxy handler and forwarded as X-Emby-Token.
	if receivedToken != "forwarded-token-value" {
		t.Errorf("expected X-Emby-Token 'forwarded-token-value', got %q", receivedToken)
	}
}
