package handler_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
)

func TestHealth_BothHealthy(t *testing.T) {
	// Set up a mock Emby server that responds to /System/Info.
	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ServerName":"Emby"}`)
	}))
	defer embyServer.Close()

	database, err := db.Open("file::memory:?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	embyClient := emby.NewClient(embyServer.URL, "test-api-key")

	h := handler.Health(database, embyClient)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %q", resp["status"])
	}
	if resp["db"] != "up" {
		t.Errorf("expected db 'up', got %q", resp["db"])
	}
	if resp["emby"] != "up" {
		t.Errorf("expected emby 'up', got %q", resp["emby"])
	}
}

func TestHealth_EmbyDown(t *testing.T) {
	// Set up a mock Emby server that returns 500.
	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer embyServer.Close()

	database, err := db.Open("file::memory:?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

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

func TestHealth_EmbyUnreachable(t *testing.T) {
	// Use a client pointing to a non-existent server.
	database, err := db.Open("file::memory:?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	embyClient := emby.NewClient("http://127.0.0.1:1", "test-api-key")

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

func TestHealth_DBDown(t *testing.T) {
	// Set up a mock Emby server that responds OK.
	embyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ServerName":"Emby"}`)
	}))
	defer embyServer.Close()

	// Open a database and then close it to simulate DB being down.
	database, err := db.Open("file::memory:?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	database.Close()

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
