package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/password"
)

// AuthTokenFromContext retrieves the Emby auth token from the request context.
// This delegates to handler.AuthTokenFromContext to ensure the same context key is used.
func AuthTokenFromContext(ctx context.Context) string {
	return handler.AuthTokenFromContext(ctx)
}

// OIDCHeaders holds extracted OIDC session headers.
type OIDCHeaders struct {
	Email       string
	DisplayName string
	PictureURL  string
}

// Auth returns middleware that extracts headers, provisions users, and authenticates with Emby.
func Auth(embyClient *emby.Client, database *db.DB, templateUserID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract OIDC headers.
			headers := OIDCHeaders{
				Email:       r.Header.Get("X-Forwarded-Email"),
				DisplayName: r.Header.Get("X-Forwarded-User"),
				PictureURL:  r.Header.Get("X-Forwarded-Picture"),
			}

			// X-Forwarded-Email is required.
			if headers.Email == "" {
				slog.Warn("missing X-Forwarded-Email header",
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			slog.Info("processing authentication",
				"email", headers.Email,
			)

			// Lookup user in database.
			record, err := database.FindUser(headers.Email)
			if err != nil {
				slog.Error("database lookup failed",
					"email", headers.Email,
					"error", err,
				)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			var userPassword string
			var embyUserID string

			if record != nil {
				// User exists in DB — use stored password.
				userPassword = record.Password
				embyUserID = record.EmbyUserID
				slog.Info("user found in database",
					"email", headers.Email,
					"emby_user_id", embyUserID,
				)
			} else {
				// User not in DB — check if user exists in Emby.
				existingUser, err := embyClient.FindUserByName(ctx, headers.Email)
				if err != nil {
					slog.Error("emby user lookup failed",
						"email", headers.Email,
						"error", err,
					)
					http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
					return
				}

				// Generate a new password.
				userPassword = password.Generate()

				if existingUser != nil {
					// User exists in Emby but not in DB — adopt user.
					embyUserID = existingUser.ID
					slog.Info("adopting existing Emby user",
						"email", headers.Email,
						"emby_user_id", embyUserID,
					)

					// Update password in Emby.
					if err := embyClient.UpdatePassword(ctx, embyUserID, userPassword); err != nil {
						slog.Error("failed to update password for adopted user",
							"email", headers.Email,
							"emby_user_id", embyUserID,
							"error", err,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
				} else {
					// User doesn't exist anywhere — create new user.
					slog.Info("provisioning new user",
						"email", headers.Email,
					)

					newUser, err := embyClient.CreateUser(ctx, headers.Email, templateUserID)
					if err != nil {
						slog.Error("failed to create user in Emby",
							"email", headers.Email,
							"error", err,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					embyUserID = newUser.ID

					// Set password.
					if err := embyClient.UpdatePassword(ctx, embyUserID, userPassword); err != nil {
						slog.Error("failed to set password for new user",
							"email", headers.Email,
							"emby_user_id", embyUserID,
							"error", err,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Update policy: enable user, disable preference access.
					policy := &emby.UserPolicy{
						IsDisabled:                 false,
						EnableUserPreferenceAccess: false,
					}
					if err := embyClient.UpdatePolicy(ctx, embyUserID, policy); err != nil {
						slog.Error("failed to update policy for new user",
							"email", headers.Email,
							"emby_user_id", embyUserID,
							"error", err,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
				}

				// Store user in database.
				if err := database.InsertUser(headers.Email, embyUserID, userPassword); err != nil {
					slog.Error("failed to store user in database",
						"email", headers.Email,
						"emby_user_id", embyUserID,
						"error", err,
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				slog.Info("user provisioned successfully",
					"email", headers.Email,
					"emby_user_id", embyUserID,
				)
			}

			// Authenticate with Emby.
			authResult, err := embyClient.AuthenticateByName(ctx, headers.Email, userPassword)
			if err != nil {
				slog.Error("authentication with Emby failed",
					"email", headers.Email,
					"error", err,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			slog.Info("authenticated with Emby",
				"email", headers.Email,
				"emby_user_id", authResult.User.ID,
			)

			// Non-blocking: set profile image if X-Forwarded-Picture is present.
			if headers.PictureURL != "" {
				go func() {
					if err := embyClient.SetProfileImage(context.Background(), embyUserID, headers.PictureURL); err != nil {
						slog.Warn("failed to set profile image",
							"email", headers.Email,
							"emby_user_id", embyUserID,
							"error", err,
						)
					}
				}()
			}

			// Non-blocking: disable EnableUserPreferenceAccess.
			go func() {
				policy := &emby.UserPolicy{
					IsDisabled:                 false,
					EnableUserPreferenceAccess: false,
				}
				if err := embyClient.UpdatePolicy(context.Background(), embyUserID, policy); err != nil {
					slog.Warn("failed to disable user preference access",
						"email", headers.Email,
						"emby_user_id", embyUserID,
						"error", err,
					)
				}
			}()

			// Store auth token in context for downstream handlers.
			ctx = handler.WithAuthToken(ctx, authResult.AccessToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
