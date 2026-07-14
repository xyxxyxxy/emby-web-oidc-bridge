package emby

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// User represents an Emby user record from the API.
type User struct {
	ID                    string
	Name                  string
	HasConfiguredPassword bool
	Policy                *UserPolicy
}

// UserPolicy represents Emby user policy fields.
type UserPolicy struct {
	IsDisabled                 bool
	IsHidden                   bool
	EnableUserPreferenceAccess bool
}

// AuthResult represents a successful authentication response.
type AuthResult struct {
	AccessToken string
	User        User
	ServerID    string
}

// Client wraps all Emby REST API interactions.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Emby API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// FindUserByName queries Emby for a user with the given name.
// Returns nil if no user with that name exists.
func (c *Client) FindUserByName(ctx context.Context, name string) (*User, error) {
	url := fmt.Sprintf("%s/Users/Query?api_key=%s", c.baseURL, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("emby: create find user request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("emby: find user request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("emby: find user: %w", err)
	}

	var result struct {
		Items []userJSON `json:"Items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("emby: decode find user response: %w", err)
	}

	for _, item := range result.Items {
		if item.Name == name {
			user := item.toUser()
			return &user, nil
		}
	}

	return nil, nil
}

// CreateUser creates a new Emby user with settings copied from the template user.
func (c *Client) CreateUser(ctx context.Context, name, copyFromUserID string) (*User, error) {
	url := fmt.Sprintf("%s/Users/New?api_key=%s", c.baseURL, c.apiKey)

	body := createUserRequest{
		Name:            name,
		CopyFromUserID:  copyFromUserID,
		UserCopyOptions: []string{"UserPolicy"},
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("emby: marshal create user request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("emby: create user request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("emby: create user request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("emby: create user: %w", err)
	}

	var userResp userJSON
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("emby: decode create user response: %w", err)
	}

	user := userResp.toUser()
	return &user, nil
}

// AuthenticateByName authenticates a user with Emby using username and password.
func (c *Client) AuthenticateByName(ctx context.Context, username, password string) (*AuthResult, error) {
	url := fmt.Sprintf("%s/Users/AuthenticateByName", c.baseURL)

	body := authenticateRequest{
		Username: username,
		Pw:       password,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("emby: marshal authenticate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("emby: create authenticate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Emby-Authorization", `Emby Client="EmbyAuthBridge", Device="Server", DeviceId="emby-auth-bridge", Version="1.0.0"`)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("emby: authenticate request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("emby: authenticate: %w", err)
	}

	var authResp authenticateResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("emby: decode authenticate response: %w", err)
	}

	return &AuthResult{
		AccessToken: authResp.AccessToken,
		User:        authResp.User.toUser(),
		ServerID:    authResp.ServerID,
	}, nil
}

// UpdatePassword sets a new password for the given user.
// Users with an existing password are reset first; users without one skip straight to set.
func (c *Client) UpdatePassword(ctx context.Context, userID, newPassword string) error {
	user, err := c.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("emby: get user for password update: %w", err)
	}

	url := fmt.Sprintf("%s/Users/%s/Password?api_key=%s", c.baseURL, userID, c.apiKey)

	if user.HasConfiguredPassword {
		resetBody := updatePasswordRequest{
			ID:            userID,
			ResetPassword: true,
		}

		reqBody, err := json.Marshal(resetBody)
		if err != nil {
			return fmt.Errorf("emby: marshal reset password request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
		if err != nil {
			return fmt.Errorf("emby: create reset password request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("emby: reset password request: %w", err)
		}
		_ = resp.Body.Close()

		if err := checkResponse(resp); err != nil {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
				return fmt.Errorf("emby: reset password: %w", err)
			}
			// Some users report HasConfiguredPassword=true but reset still returns 400
			// (e.g. blank password edge cases). Fall through to set-only.
		}
	}

	// Set the new password.
	setBody := updatePasswordRequest{
		ID:    userID,
		NewPw: newPassword,
	}

	reqBody, err := json.Marshal(setBody)
	if err != nil {
		return fmt.Errorf("emby: marshal set password request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("emby: create set password request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emby: set password request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("emby: set password: %w", err)
	}

	return nil
}

// GetUser fetches a user record from Emby by ID.
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	url := fmt.Sprintf("%s/Users/%s?api_key=%s", c.baseURL, userID, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("emby: create get user request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("emby: get user request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("emby: get user: %w", err)
	}

	var userResp userJSON
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return nil, fmt.Errorf("emby: decode user response: %w", err)
	}

	user := userResp.toUser()
	return &user, nil
}

// GetUserPolicy fetches the full policy JSON for a user.
// Returns the raw JSON bytes so all fields are preserved.
func (c *Client) GetUserPolicy(ctx context.Context, userID string) ([]byte, error) {
	url := fmt.Sprintf("%s/Users/%s?api_key=%s", c.baseURL, userID, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("emby: create get user request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("emby: get user request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("emby: get user: %w", err)
	}

	var user struct {
		Policy json.RawMessage `json:"Policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("emby: decode user response: %w", err)
	}

	return user.Policy, nil
}

// UpdatePolicyRaw updates the policy for the given user using raw JSON bytes.
// This preserves all policy fields from the source without needing to enumerate them.
func (c *Client) UpdatePolicyRaw(ctx context.Context, userID string, policyJSON []byte) error {
	url := fmt.Sprintf("%s/Users/%s/Policy?api_key=%s", c.baseURL, userID, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(policyJSON))
	if err != nil {
		return fmt.Errorf("emby: create update policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emby: update policy request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("emby: update policy: %w", err)
	}

	return nil
}

// UpdatePolicy updates the policy for the given user.
func (c *Client) UpdatePolicy(ctx context.Context, userID string, policy *UserPolicy) error {
	url := fmt.Sprintf("%s/Users/%s/Policy?api_key=%s", c.baseURL, userID, c.apiKey)

	body := userPolicyJSON{
		IsDisabled:                 policy.IsDisabled,
		IsHidden:                   policy.IsHidden,
		EnableUserPreferenceAccess: policy.EnableUserPreferenceAccess,
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("emby: marshal update policy request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("emby: create update policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emby: update policy request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("emby: update policy: %w", err)
	}

	return nil
}

// SetProfileImage fetches an image from the given URL and sets it as the user's profile image.
func (c *Client) SetProfileImage(ctx context.Context, userID string, imageURL string) error {
	// Fetch the image from the URL.
	imgReq, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return fmt.Errorf("emby: create image fetch request: %w", err)
	}

	imgResp, err := c.httpClient.Do(imgReq)
	if err != nil {
		return fmt.Errorf("emby: fetch image: %w", err)
	}
	defer func() { _ = imgResp.Body.Close() }()

	if imgResp.StatusCode != http.StatusOK {
		return fmt.Errorf("emby: fetch image: unexpected status %d", imgResp.StatusCode)
	}

	imageBytes, err := io.ReadAll(io.LimitReader(imgResp.Body, 5*1024*1024)) // 5MB max
	if err != nil {
		return fmt.Errorf("emby: read image bytes: %w", err)
	}

	// POST base64-encoded image to Emby.
	url := fmt.Sprintf("%s/Users/%s/Images/Primary?api_key=%s", c.baseURL, userID, c.apiKey)

	encoded := base64.StdEncoding.EncodeToString(imageBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(encoded)))
	if err != nil {
		return fmt.Errorf("emby: create set image request: %w", err)
	}
	req.Header.Set("Content-Type", "image/png")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emby: set image request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("emby: set image: %w", err)
	}

	return nil
}

// UpdateUserName renames an Emby user by updating their Name field via POST /Users/{Id}.
func (c *Client) UpdateUserName(ctx context.Context, userID, newName string) error {
	url := fmt.Sprintf("%s/Users/%s?api_key=%s", c.baseURL, userID, c.apiKey)

	body := map[string]string{"Name": newName}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("emby: marshal update user name request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("emby: create update user name request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emby: update user name request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("emby: update user name: %w", err)
	}

	return nil
}

// Ping checks connectivity to the Emby server.
func (c *Client) Ping(ctx context.Context) error {
	url := fmt.Sprintf("%s/System/Info?api_key=%s", c.baseURL, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("emby: create ping request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("emby: ping request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkResponse(resp); err != nil {
		return fmt.Errorf("emby: ping: %w", err)
	}

	return nil
}
