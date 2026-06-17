package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
)

// credentialsResponse is the JSON response for the credentials endpoint.
type credentialsResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// credentialsError is the JSON error response for the credentials endpoint.
type credentialsError struct {
	Error string `json:"error"`
}

// Credentials returns an http.HandlerFunc that serves the authenticated user's
// Emby username and password as JSON. It reads the OIDC subject and resolved
// username from the request context (set by the auth middleware).
func Credentials(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		sub := AuthSubFromContext(r.Context())
		if sub == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(credentialsError{Error: "missing authentication context"})
			return
		}

		username := AuthUsernameFromContext(r.Context())

		record, err := database.FindUserBySub(sub)
		if err != nil {
			slog.Error("credentials: database error", "sub", sub, "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(credentialsError{Error: "internal server error"})
			return
		}
		if record == nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(credentialsError{Error: "user not found"})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(credentialsResponse{
			Username: username,
			Password: record.Password,
		})
	}
}
