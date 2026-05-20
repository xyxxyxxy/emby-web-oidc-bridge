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

func flowDBURI() string {
	n := flowDBCounter.Add(1)
	return fmt.Sprintf("file:flow%d?mode=memory&cache=shared", n)
}

type apiCall struct {
	Method string
	Path   string
}

func buildFullChain(trustedCIDRs []*net.IPNet, embyClient *emby.Client, database *db.DB, templateUserID string, backendURL string) http.Handler {
	templatePolicy := []byte(`{"IsDisabled":true,"IsHidden":true,"EnableUserPreferenceAccess":true}`)
	proxyHandler := handler.Proxy(backendURL)
	authMiddleware := middleware.Auth(embyClient, database, templateUserID, templatePolicy, "")
	trustedProxyMiddleware := middleware.TrustedProxy(trustedCIDRs)

	return trustedProxyMiddleware(authMiddleware(proxyHandler))
}

func parseTrustedCIDRs(cidr string) []*net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR in test: %s", cidr))
	}
	return []*net.IPNet{network}
}

// TestIntegration_NewUserProvisioningFlow tests the complete provisioning flow.
func TestIntegration_NewUserProvisioningFlow(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	var mu sync.Mutex
	var calls []apiCall

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, apiCall{Method: r.Method, Path: r.URL.Path})
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/Users/Query":
			resp := map[string]interface{}{"Items": []map[string]interface{}{}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/New":
			var body struct {
				Name           string `json:"Name"`
				CopyFromUserID string `json:"CopyFromUserId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Name != "New User" {
				t.Errorf("CreateUser: expected Name 'New User', got %q", body.Name)
			}
			if body.CopyFromUserID != "template-id-001" {
				t.Errorf("CreateUser: expected CopyFromUserId 'template-id-001', got %q", body.CopyFromUserID)
			}
			resp := map[string]interface{}{"Id": "created-user-001", "Name": "New User"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/created-user-001/Password":
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/created-user-001/Policy":
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodGet && r.URL.Path == "/Users/created-user-001":
			resp := map[string]interface{}{
				"Id": "created-user-001", "Name": "New User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "new-user-token-xyz",
				"User":        map[string]interface{}{"Id": "created-user-001", "Name": "New User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer embySrv.Close()

	var receivedToken string
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-Emby-Token")
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend OK"))
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")
	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Items/123", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Sub", "sub-new-integration")
	req.Header.Set("X-Forwarded-User", "New User")
	req.Header.Set("X-Forwarded-Email", "newuser@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "backend OK" {
		t.Errorf("expected body 'backend OK', got %q", rec.Body.String())
	}
	if receivedToken != "new-user-token-xyz" {
		t.Errorf("expected X-Emby-Token 'new-user-token-xyz', got %q", receivedToken)
	}
	if receivedPath != "/Items/123" {
		t.Errorf("expected path '/Items/123', got %q", receivedPath)
	}

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

	if len(mainCalls) < len(expectedOrder) {
		t.Fatalf("expected at least %d API calls, got %d: %+v", len(expectedOrder), len(mainCalls), mainCalls)
	}
	for i, expected := range expectedOrder {
		if mainCalls[i].Method != expected.Method || mainCalls[i].Path != expected.Path {
			t.Errorf("call[%d]: expected %s %s, got %s %s", i, expected.Method, expected.Path, mainCalls[i].Method, mainCalls[i].Path)
		}
	}

	record, err := database.FindUserBySub("sub-new-integration")
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

// TestIntegration_ExistingUserLoginFlow tests the login flow for a user already in the DB.
func TestIntegration_ExistingUserLoginFlow(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-existing", "Existing User", "existing@example.com", "emby-user-100", "mypassw1")
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
			_ = json.NewDecoder(r.Body).Decode(&body)
			authPassword = body.Pw

			if body.Username != "Existing User" {
				t.Errorf("expected username 'Existing User', got %q", body.Username)
			}

			resp := map[string]interface{}{
				"AccessToken": "existing-token-abc",
				"User":        map[string]interface{}{"Id": "emby-user-100", "Name": "Existing User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/emby-user-100/Policy":
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodGet && r.URL.Path == "/Users/emby-user-100":
			resp := map[string]interface{}{
				"Id": "emby-user-100", "Name": "Existing User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

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
		_, _ = w.Write([]byte("proxied"))
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")
	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/web/index.html", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-Sub", "sub-existing")
	req.Header.Set("X-Forwarded-User", "Existing User")
	req.Header.Set("X-Forwarded-Email", "existing@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "proxied" {
		t.Errorf("expected body 'proxied', got %q", rec.Body.String())
	}
	if authPassword != "mypassw1" {
		t.Errorf("expected auth password 'mypassw1', got %q", authPassword)
	}
	if receivedToken != "existing-token-abc" {
		t.Errorf("expected X-Emby-Token 'existing-token-abc', got %q", receivedToken)
	}

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

// TestIntegration_AdoptedUserFlow tests the flow when a user exists in Emby but not in the DB.
func TestIntegration_AdoptedUserFlow(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	var mu sync.Mutex
	var calls []apiCall

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, apiCall{Method: r.Method, Path: r.URL.Path})
		mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/Users/Query":
			resp := map[string]interface{}{
				"Items": []map[string]interface{}{
					{"Id": "adopted-emby-555", "Name": "Adopted User"},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/adopted-emby-555/Password":
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/adopted-emby-555/Policy":
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodGet && r.URL.Path == "/Users/adopted-emby-555":
			resp := map[string]interface{}{
				"Id": "adopted-emby-555", "Name": "Adopted User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "adopted-token-999",
				"User":        map[string]interface{}{"Id": "adopted-emby-555", "Name": "Adopted User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

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
		_, _ = w.Write([]byte("adopted OK"))
	}))
	defer backend.Close()

	embyClient := emby.NewClient(embySrv.URL, "test-api-key")
	trustedCIDRs := parseTrustedCIDRs("127.0.0.0/8")
	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Library", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-Sub", "sub-adopted-int")
	req.Header.Set("X-Forwarded-User", "Adopted User")
	req.Header.Set("X-Forwarded-Email", "adopted@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "adopted OK" {
		t.Errorf("expected body 'adopted OK', got %q", rec.Body.String())
	}
	if receivedToken != "adopted-token-999" {
		t.Errorf("expected X-Emby-Token 'adopted-token-999', got %q", receivedToken)
	}

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

	for _, c := range syncCalls {
		if c.Path == "/Users/New" {
			t.Error("CreateUser should NOT have been called for adopted user")
		}
	}

	record, err := database.FindUserBySub("sub-adopted-int")
	if err != nil {
		t.Fatalf("failed to find user in db: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record in db, got nil")
	}
	if record.EmbyUserID != "adopted-emby-555" {
		t.Errorf("expected emby_user_id 'adopted-emby-555', got %q", record.EmbyUserID)
	}
}

// TestIntegration_RequestBodyPreserved verifies that request body is preserved through the full chain.
func TestIntegration_RequestBodyPreserved(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-body", "Body User", "body@example.com", "emby-body-user", "bodypass1")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "body-token",
				"User":        map[string]interface{}{"Id": "emby-body-user", "Name": "Body User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/Users/emby-body-user/Policy":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/Users/emby-body-user":
			resp := map[string]interface{}{
				"Id": "emby-body-user", "Name": "Body User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
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
	req.Header.Set("X-Forwarded-Sub", "sub-body")
	req.Header.Set("X-Forwarded-User", "Body User")
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

// TestIntegration_AuthTokenForwardedToProxy verifies that the auth token is forwarded as X-Emby-Token.
func TestIntegration_AuthTokenForwardedToProxy(t *testing.T) {
	database, err := db.Open(flowDBURI())
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-token", "Token User", "token@example.com", "emby-token-user", "tokenpw1")
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/Users/AuthenticateByName":
			resp := map[string]interface{}{
				"AccessToken": "forwarded-token-value",
				"User":        map[string]interface{}{"Id": "emby-token-user", "Name": "Token User"},
				"ServerId":    "server-1",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && r.URL.Path == "/Users/emby-token-user/Policy":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/Users/emby-token-user":
			resp := map[string]interface{}{
				"Id": "emby-token-user", "Name": "Token User",
				"Policy": map[string]interface{}{"IsDisabled": false, "IsHidden": true, "EnableUserPreferenceAccess": false},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
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
	chain := buildFullChain(trustedCIDRs, embyClient, database, "template-id-001", backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/Items", nil)
	req.RemoteAddr = "127.0.0.1:22222"
	req.Header.Set("X-Forwarded-Sub", "sub-token")
	req.Header.Set("X-Forwarded-User", "Token User")
	req.Header.Set("X-Forwarded-Email", "token@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if receivedToken != "forwarded-token-value" {
		t.Errorf("expected X-Emby-Token 'forwarded-token-value', got %q", receivedToken)
	}
}
