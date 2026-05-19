package emby

import (
	"fmt"
	"net/http"
)

// Request/response structs for JSON marshaling (internal to the package).

type createUserRequest struct {
	Name            string   `json:"Name"`
	CopyFromUserID  string   `json:"CopyFromUserId"`
	UserCopyOptions []string `json:"UserCopyOptions"`
}

type authenticateRequest struct {
	Username string `json:"Username"`
	Pw       string `json:"Pw"`
}

type authenticateResponse struct {
	AccessToken string   `json:"AccessToken"`
	User        userJSON `json:"User"`
	ServerID    string   `json:"ServerId"`
}

type userJSON struct {
	ID     string          `json:"Id"`
	Name   string          `json:"Name"`
	Policy *userPolicyJSON `json:"Policy,omitempty"`
}

type userPolicyJSON struct {
	IsDisabled                 bool `json:"IsDisabled"`
	IsHidden                   bool `json:"IsHidden"`
	EnableUserPreferenceAccess bool `json:"EnableUserPreferenceAccess"`
}

type updatePasswordRequest struct {
	ID            string `json:"Id"`
	NewPw         string `json:"NewPw"`
	ResetPassword bool   `json:"ResetPassword"`
}

// toUser converts a userJSON to the public User type.
func (u userJSON) toUser() User {
	user := User{
		ID:   u.ID,
		Name: u.Name,
	}
	if u.Policy != nil {
		user.Policy = &UserPolicy{
			IsDisabled:                 u.Policy.IsDisabled,
			IsHidden:                   u.Policy.IsHidden,
			EnableUserPreferenceAccess: u.Policy.EnableUserPreferenceAccess,
		}
	}
	return user
}

// APIError represents an error response from the Emby API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("emby API error: status %d: %s", e.StatusCode, e.Message)
}

// checkResponse checks the HTTP response status code and returns an error for non-2xx responses.
func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    http.StatusText(resp.StatusCode),
	}
}
