package integration_test

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/middleware"
)

var errorDBCounter atomic.Int64

// testTemplatePolicy is a valid JSON policy used as the templatePolicy argument in tests.
var testTemplatePolicy = []byte(`{"IsDisabled":true,"IsHidden":true,"EnableUserPreferenceAccess":true}`)

func errorDBURI() string {
	n := errorDBCounter.Add(1)
	return fmt.Sprintf("file:integrationerr%d?mode=memory&cache=shared", n)
}

func parseErrorCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("failed to parse CIDR %q: %v", cidr, err)
	}
	return network
}

// buildErrorChain creates the full middleware chain: TrustedProxy → Auth → final handler.
func buildErrorChain(trusted []*net.IPNet, embyClient *emby.Client, database *db.DB) http.Handler {
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	})

	authMiddleware := middleware.Auth(embyClient, database, "template-user-id", testTemplatePolicy, "")
	proxyMiddleware := middleware.TrustedProxy(trusted)

	return proxyMiddleware(authMiddleware(finalHandler))
}

// TestIntegrationError_UntrustedIPRejection verifies that a request from an untrusted IP
// is rejected with 403 Forbidden through the full middleware chain.
// Validates: Requirements 1.2
func TestIntegrationError_UntrustedIPRejection(t *testing.T) {
	database, err := db.Open(errorDBURI())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = database.Close() }()

	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Emby server should not be called for untrusted IP")
	}))
	defer embyServer.Close()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	// Only trust 10.0.0.0/8 — request will come from 192.168.1.1.
	trusted := []*net.IPNet{parseErrorCIDR(t, "10.0.0.0/8")}
	chain := buildErrorChain(trusted, embyClient, database)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:54321" // Untrusted IP.
	req.Header.Set("X-Forwarded-Email", "user@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

// TestIntegrationError_MissingSub verifies that a request from a trusted IP
// without a sub claim is rejected with 401 Unauthorized.
// Validates: Requirements 1.4
func TestIntegrationError_MissingSub(t *testing.T) {
	database, err := db.Open(errorDBURI())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = database.Close() }()

	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Emby server should not be called when sub is missing")
	}))
	defer embyServer.Close()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	// Trust 127.0.0.0/8 — request will come from 127.0.0.1.
	trusted := []*net.IPNet{parseErrorCIDR(t, "127.0.0.0/8")}
	chain := buildErrorChain(trusted, embyClient, database)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345" // Trusted IP.
	// No sub header or JWT — only email.
	req.Header.Set("X-Forwarded-Email", "user@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

// TestIntegrationError_EmbyAPIUnreachable verifies that when the Emby API is unreachable
// (user not in DB, needs to query Emby), a 503 Service Unavailable is returned.
// Validates: Requirements 2.4
func TestIntegrationError_EmbyAPIUnreachable(t *testing.T) {
	database, err := db.Open(errorDBURI())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = database.Close() }()

	// Create and immediately close a server to simulate unreachable Emby.
	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	embyServer.Close()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	trusted := []*net.IPNet{parseErrorCIDR(t, "127.0.0.0/8")}
	chain := buildErrorChain(trusted, embyClient, database)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Sub", "sub-unreachable")
	req.Header.Set("X-Forwarded-Preferred-Username", "unreachable")
	req.Header.Set("X-Forwarded-Email", "unreachable@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
}

// TestIntegrationError_UserCreationFailure verifies that when user creation in Emby fails
// (returns 500), the bridge returns 500 Internal Server Error.
// Validates: Requirements 3.5
func TestIntegrationError_UserCreationFailure(t *testing.T) {
	database, err := db.Open(errorDBURI())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = database.Close() }()

	mux := http.NewServeMux()
	// FindUserByName — user not found in Emby.
	mux.HandleFunc("/Users/Query", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Items": []map[string]interface{}{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	// CreateUser — returns 500 to simulate failure.
	mux.HandleFunc("/Users/New", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	embyServer := httptest.NewServer(mux)
	defer embyServer.Close()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	trusted := []*net.IPNet{parseErrorCIDR(t, "127.0.0.0/8")}
	chain := buildErrorChain(trusted, embyClient, database)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Sub", "sub-failcreate")
	req.Header.Set("X-Forwarded-Preferred-Username", "failcreate")
	req.Header.Set("X-Forwarded-Email", "failcreate@example.com")
	rec := httptest.NewRecorder()

	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
}

// TestIntegrationError_HealthCheckDBDown verifies that the health check returns 503
// when the database is unreachable.
// Validates: Requirements 14.4
func TestIntegrationError_HealthCheckDBDown(t *testing.T) {
	// Set up a healthy Emby server.
	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"ServerName":"Emby"}`)
	}))
	defer embyServer.Close()

	// Open and immediately close the database to simulate DB down.
	database, err := db.Open(errorDBURI())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	_ = database.Close()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	h := handler.Health(database, embyClient)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "unhealthy" {
		t.Errorf("expected status 'unhealthy', got %q", resp["status"])
	}
	if resp["db"] != "down" {
		t.Errorf("expected db 'down', got %q", resp["db"])
	}
}

// TestIntegrationError_HealthCheckEmbyDown verifies that the health check returns 503
// when the Emby API returns a 500 error.
// Validates: Requirements 14.5
func TestIntegrationError_HealthCheckEmbyDown(t *testing.T) {
	// Set up an Emby server that returns 500.
	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer embyServer.Close()

	database, err := db.Open(errorDBURI())
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = database.Close() }()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	h := handler.Health(database, embyClient)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "unhealthy" {
		t.Errorf("expected status 'unhealthy', got %q", resp["status"])
	}
	if resp["emby"] != "down" {
		t.Errorf("expected emby 'down', got %q", resp["emby"])
	}
}
