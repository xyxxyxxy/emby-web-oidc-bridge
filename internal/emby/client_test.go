package emby

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFindUserByName_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/Users/Query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("unexpected api_key: %s", r.URL.Query().Get("api_key"))
		}

		resp := map[string]interface{}{
			"Items": []map[string]interface{}{
				{"Id": "user-123", "Name": "alice@example.com"},
				{"Id": "user-456", "Name": "bob@example.com"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	user, err := client.FindUserByName(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.ID != "user-123" {
		t.Errorf("user.ID = %q, want %q", user.ID, "user-123")
	}
	if user.Name != "alice@example.com" {
		t.Errorf("user.Name = %q, want %q", user.Name, "alice@example.com")
	}
}

func TestFindUserByName_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"Items": []map[string]interface{}{
				{"Id": "user-456", "Name": "bob@example.com"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	user, err := client.FindUserByName(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestCreateUser_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/Users/New" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("unexpected api_key: %s", r.URL.Query().Get("api_key"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}

		// Verify request body
		var body createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body.Name != "alice@example.com" {
			t.Errorf("body.Name = %q, want %q", body.Name, "alice@example.com")
		}
		if body.CopyFromUserID != "template-user-id" {
			t.Errorf("body.CopyFromUserID = %q, want %q", body.CopyFromUserID, "template-user-id")
		}
		if len(body.UserCopyOptions) != 2 || body.UserCopyOptions[0] != "UserPolicy" || body.UserCopyOptions[1] != "UserConfiguration" {
			t.Errorf("body.UserCopyOptions = %v, want [UserPolicy, UserConfiguration]", body.UserCopyOptions)
		}

		resp := map[string]interface{}{
			"Id":   "new-user-789",
			"Name": "alice@example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	user, err := client.CreateUser(context.Background(), "alice@example.com", "template-user-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "new-user-789" {
		t.Errorf("user.ID = %q, want %q", user.ID, "new-user-789")
	}
	if user.Name != "alice@example.com" {
		t.Errorf("user.Name = %q, want %q", user.Name, "alice@example.com")
	}
}

func TestAuthenticateByName_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/Users/AuthenticateByName" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Verify X-Emby-Authorization header
		authHeader := r.Header.Get("X-Emby-Authorization")
		expected := `Emby Client="EmbyAuthBridge", Device="Server", DeviceId="emby-auth-bridge", Version="1.0.0"`
		if authHeader != expected {
			t.Errorf("X-Emby-Authorization = %q, want %q", authHeader, expected)
		}

		// Verify no api_key query param (uses header auth instead)
		if r.URL.Query().Get("api_key") != "" {
			t.Errorf("unexpected api_key query param for AuthenticateByName")
		}

		// Verify request body
		var body authenticateRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body.Username != "alice@example.com" {
			t.Errorf("body.Username = %q, want %q", body.Username, "alice@example.com")
		}
		if body.Pw != "abc12def" {
			t.Errorf("body.Pw = %q, want %q", body.Pw, "abc12def")
		}

		resp := authenticateResponse{
			AccessToken: "token-xyz",
			User:        userJSON{ID: "user-123", Name: "alice@example.com"},
			ServerID:    "server-abc",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	result, err := client.AuthenticateByName(context.Background(), "alice@example.com", "abc12def")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessToken != "token-xyz" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "token-xyz")
	}
	if result.User.ID != "user-123" {
		t.Errorf("User.ID = %q, want %q", result.User.ID, "user-123")
	}
	if result.ServerID != "server-abc" {
		t.Errorf("ServerID = %q, want %q", result.ServerID, "server-abc")
	}
}

func TestAuthenticateByName_HeaderFormat(t *testing.T) {
	var capturedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Emby-Authorization")
		resp := authenticateResponse{
			AccessToken: "token",
			User:        userJSON{ID: "id", Name: "name"},
			ServerID:    "srv",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	_, err := client.AuthenticateByName(context.Background(), "user", "pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `Emby Client="EmbyAuthBridge", Device="Server", DeviceId="emby-auth-bridge", Version="1.0.0"`
	if capturedHeader != expected {
		t.Errorf("X-Emby-Authorization header:\n  got:  %q\n  want: %q", capturedHeader, expected)
	}
}

func TestUpdatePassword_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/Users/user-123/Password" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("unexpected api_key: %s", r.URL.Query().Get("api_key"))
		}

		// Verify request body
		var body updatePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body.ID != "user-123" {
			t.Errorf("body.ID = %q, want %q", body.ID, "user-123")
		}
		if body.NewPw != "newpass1" {
			t.Errorf("body.NewPw = %q, want %q", body.NewPw, "newpass1")
		}
		if !body.ResetPassword {
			t.Error("body.ResetPassword = false, want true")
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	err := client.UpdatePassword(context.Background(), "user-123", "newpass1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdatePolicy_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/Users/user-123/Policy" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("unexpected api_key: %s", r.URL.Query().Get("api_key"))
		}

		// Verify request body
		var body userPolicyJSON
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body.IsDisabled != false {
			t.Errorf("body.IsDisabled = %v, want false", body.IsDisabled)
		}
		if body.EnableUserPreferenceAccess != false {
			t.Errorf("body.EnableUserPreferenceAccess = %v, want false", body.EnableUserPreferenceAccess)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	policy := &UserPolicy{
		IsDisabled:                 false,
		EnableUserPreferenceAccess: false,
	}
	err := client.UpdatePolicy(context.Background(), "user-123", policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetProfileImage_Success(t *testing.T) {
	// Image server that serves a fake image
	imageData := []byte("fake-image-bytes-png")
	imageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(imageData)
	}))
	defer imageSrv.Close()

	// Emby server that receives the image
	var receivedBody []byte
	var receivedContentType string
	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/Users/user-123/Images/Primary" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("unexpected api_key: %s", r.URL.Query().Get("api_key"))
		}
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer embySrv.Close()

	client := NewClient(embySrv.URL, "test-key")
	err := client.SetProfileImage(context.Background(), "user-123", imageSrv.URL+"/avatar.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(receivedBody) != string(imageData) {
		t.Errorf("received body = %q, want %q", receivedBody, imageData)
	}
	if receivedContentType != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/octet-stream")
	}
}

func TestSetProfileImage_ImageFetchFails(t *testing.T) {
	// Image server returns 404
	imageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer imageSrv.Close()

	embySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Emby should not be called when image fetch fails")
	}))
	defer embySrv.Close()

	client := NewClient(embySrv.URL, "test-key")
	err := client.SetProfileImage(context.Background(), "user-123", imageSrv.URL+"/missing.png")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestPing_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/System/Info" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("api_key") != "test-key" {
			t.Errorf("unexpected api_key: %s", r.URL.Query().Get("api_key"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ServerName":"Emby"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPing_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	err := client.Ping(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestErrorHandling_4xx(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"403 Forbidden", http.StatusForbidden},
		{"404 Not Found", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			client := NewClient(srv.URL, "test-key")
			err := client.Ping(context.Background())
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestErrorHandling_5xx(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"502 Bad Gateway", http.StatusBadGateway},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			client := NewClient(srv.URL, "test-key")
			_, err := client.FindUserByName(context.Background(), "test")
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %T: %v", err, err)
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestErrorHandling_4xx_CreateUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	_, err := client.CreateUser(context.Background(), "test", "template-id")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusBadRequest)
	}
}

func TestErrorHandling_5xx_AuthenticateByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	_, err := client.AuthenticateByName(context.Background(), "user", "pass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestErrorHandling_4xx_UpdatePassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	err := client.UpdatePassword(context.Background(), "user-123", "newpass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusForbidden)
	}
}

func TestErrorHandling_5xx_UpdatePolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "test-key")
	err := client.UpdatePolicy(context.Background(), "user-123", &UserPolicy{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("APIError.StatusCode = %d, want %d", apiErr.StatusCode, http.StatusInternalServerError)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	client := NewClient("http://emby:8096/emby/", "key")
	if client.baseURL != "http://emby:8096/emby" {
		t.Errorf("baseURL = %q, want trailing slash trimmed", client.baseURL)
	}
}
