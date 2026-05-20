package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/emby"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/handler"
	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/password"
)

// pictureSyncInFlight tracks users with an in-flight profile image sync
// to prevent concurrent goroutines from hitting rate limits.
var pictureSyncInFlight sync.Map

// sessionCache stores cached auth sessions per user email to avoid
// re-authenticating with Emby on every request.
// Key: email (string), Value: *cachedSession
var sessionCache sync.Map

type cachedSession struct {
	accessToken string
	userID      string
	serverID    string
	embyUserID  string
}

// clearSessionCache removes all entries from the session cache.
// This is intended for use in tests to ensure isolation between test cases.
func clearSessionCache() {
	sessionCache.Range(func(key, value interface{}) bool {
		sessionCache.Delete(key)
		return true
	})
}

// buildUserPolicy takes the template policy JSON and overrides IsDisabled and
// EnableUserPreferenceAccess, preserving all other fields from the template.
func buildUserPolicy(templatePolicy []byte) ([]byte, error) {
	var policy map[string]interface{}
	if err := json.Unmarshal(templatePolicy, &policy); err != nil {
		return nil, err
	}
	policy["IsDisabled"] = false
	policy["EnableUserPreferenceAccess"] = false
	return json.Marshal(policy)
}

// extractPictureFromJWT decodes the payload of a JWT token (without signature verification)
// and extracts the "picture" claim. Returns empty string if not found or on error.
// Signature verification is not needed because the token was already validated by oauth2-proxy.
func extractPictureFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	// Decode the payload (second part). Add padding if needed.
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var claims struct {
		Picture string `json:"picture"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return ""
	}
	return claims.Picture
}

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
func Auth(embyClient *emby.Client, database *db.DB, templateUserID string, templatePolicy []byte, oidcIssuerURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract OIDC headers.
			// Support both X-Forwarded-* (oauth2-proxy upstream mode) and
			// X-Auth-Request-* (oauth2-proxy forward_auth/subrequest mode).
			email := r.Header.Get("X-Forwarded-Email")
			if email == "" {
				email = r.Header.Get("X-Auth-Request-Email")
			}
			displayName := r.Header.Get("X-Forwarded-User")
			if displayName == "" {
				displayName = r.Header.Get("X-Auth-Request-User")
			}
			headers := OIDCHeaders{
				Email:       email,
				DisplayName: displayName,
				PictureURL:  r.Header.Get("X-Forwarded-Picture"),
			}

			if headers.PictureURL == "" {
				headers.PictureURL = r.Header.Get("X-Auth-Request-Picture")
			}

			// Email is required.
			if headers.Email == "" {
				slog.Warn("missing X-Forwarded-Email header",
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check session cache — if we have a cached session, skip everything.
			if cached, ok := sessionCache.Load(headers.Email); ok {
				session := cached.(*cachedSession)
				ctx = handler.WithAuthSession(ctx, session.accessToken, session.userID, session.serverID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// If no picture URL from headers, try fetching from OIDC userinfo endpoint.
			if headers.PictureURL == "" && oidcIssuerURL != "" {
				accessToken := r.Header.Get("X-Forwarded-Access-Token")
				if accessToken == "" {
					accessToken = r.Header.Get("X-Auth-Request-Access-Token")
				}
				if accessToken != "" {
					userinfoURL := strings.TrimRight(oidcIssuerURL, "/") + "/userinfo"
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
					if err == nil {
						req.Header.Set("Authorization", "Bearer "+accessToken)
						resp, err := http.DefaultClient.Do(req)
						if err == nil {
							defer resp.Body.Close()
							if resp.StatusCode == http.StatusOK {
								var claims struct {
									Picture string `json:"picture"`
								}
								if json.NewDecoder(resp.Body).Decode(&claims) == nil && claims.Picture != "" {
									headers.PictureURL = claims.Picture
									slog.Info("fetched picture URL from userinfo", "picture_url", headers.PictureURL)
								}
							}
						} else {
							slog.Warn("failed to fetch userinfo", "error", err)
						}
					}
				}
			}

			// If still no picture URL, try extracting from JWT in Authorization header.
			// oauth2-proxy with set_authorization_header=true forwards the ID token.
			if headers.PictureURL == "" {
				authHeader := r.Header.Get("Authorization")
				if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
					token := authHeader[7:]
					if picture := extractPictureFromJWT(token); picture != "" {
						headers.PictureURL = picture
						slog.Info("extracted picture URL from ID token", "picture_url", headers.PictureURL)
					}
				}
			}

			// Email is required.
			if headers.Email == "" {
				slog.Warn("missing X-Forwarded-Email header",
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			slog.Info("processing authentication",
				"email", headers.Email,
				"picture_url", headers.PictureURL,
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

					// Update policy: enable user, disable preference access, preserve template settings.
					policyJSON, polBuildErr := buildUserPolicy(templatePolicy)
					if polBuildErr != nil {
						slog.Error("failed to build user policy",
							"email", headers.Email,
							"error", polBuildErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					if err := embyClient.UpdatePolicyRaw(ctx, embyUserID, policyJSON); err != nil {
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
				// If user was in DB but auth failed, they may have been deleted from Emby.
				// Check if user still exists and re-provision if needed.
				if record != nil {
					slog.Warn("authentication failed for existing DB user, checking if user was deleted from Emby",
						"email", headers.Email,
						"emby_user_id", embyUserID,
						"error", err,
					)

					// Delete stale cache entry.
					sessionCache.Delete(headers.Email)

					existingUser, lookupErr := embyClient.FindUserByName(ctx, headers.Email)
					if lookupErr != nil {
						slog.Error("emby user lookup failed during re-provision check",
							"email", headers.Email,
							"error", lookupErr,
						)
						http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
						return
					}

					// Delete stale DB record.
					if delErr := database.DeleteUser(headers.Email); delErr != nil {
						slog.Error("failed to delete stale user record",
							"email", headers.Email,
							"error", delErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Generate a new password and re-provision.
					userPassword = password.Generate()

					if existingUser != nil {
						// User still exists in Emby (password mismatch or disabled) — update password and re-enable.
						embyUserID = existingUser.ID
						slog.Warn("re-adopting Emby user after auth failure",
							"email", headers.Email,
							"emby_user_id", embyUserID,
						)
						if pwErr := embyClient.UpdatePassword(ctx, embyUserID, userPassword); pwErr != nil {
							slog.Error("failed to update password during re-provision",
								"email", headers.Email,
								"error", pwErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						// Re-enable user in case they were disabled.
						policyJSON, polBuildErr := buildUserPolicy(templatePolicy)
						if polBuildErr == nil {
							if polErr := embyClient.UpdatePolicyRaw(ctx, embyUserID, policyJSON); polErr != nil {
								slog.Warn("failed to re-enable user during re-adoption",
									"email", headers.Email,
									"error", polErr,
								)
							}
						}
					} else {
						// User was deleted from Emby — create fresh.
						slog.Warn("user deleted from Emby, re-provisioning",
							"email", headers.Email,
						)
						newUser, createErr := embyClient.CreateUser(ctx, headers.Email, templateUserID)
						if createErr != nil {
							slog.Error("failed to re-create user in Emby",
								"email", headers.Email,
								"error", createErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						embyUserID = newUser.ID

						if pwErr := embyClient.UpdatePassword(ctx, embyUserID, userPassword); pwErr != nil {
							slog.Error("failed to set password for re-created user",
								"email", headers.Email,
								"error", pwErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						policyJSON, polBuildErr := buildUserPolicy(templatePolicy)
						if polBuildErr != nil {
							slog.Error("failed to build user policy for re-created user",
								"email", headers.Email,
								"error", polBuildErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						if polErr := embyClient.UpdatePolicyRaw(ctx, embyUserID, policyJSON); polErr != nil {
							slog.Error("failed to update policy for re-created user",
								"email", headers.Email,
								"error", polErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
					}

					// Store new record in DB.
					if insErr := database.InsertUser(headers.Email, embyUserID, userPassword); insErr != nil {
						slog.Error("failed to store re-provisioned user in database",
							"email", headers.Email,
							"error", insErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Retry authentication.
					authResult, err = embyClient.AuthenticateByName(ctx, headers.Email, userPassword)
					if err != nil {
						slog.Error("authentication still failed after re-provision",
							"email", headers.Email,
							"error", err,
						)
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}

					slog.Info("user re-provisioned and authenticated successfully",
						"email", headers.Email,
						"emby_user_id", embyUserID,
					)
				} else {
					slog.Error("authentication with Emby failed",
						"email", headers.Email,
						"error", err,
					)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			slog.Info("authenticated with Emby",
				"email", headers.Email,
				"emby_user_id", authResult.User.ID,
			)

			// Store session in cache for subsequent requests.
			sessionCache.Store(headers.Email, &cachedSession{
				accessToken: authResult.AccessToken,
				userID:      authResult.User.ID,
				serverID:    authResult.ServerID,
				embyUserID:  embyUserID,
			})

			// Non-blocking: sync profile image when URL has changed (or on first provisioning).
			// Uses pictureSyncInFlight to prevent concurrent syncs for the same user.
			if headers.PictureURL != "" {
				shouldSync := record == nil || record.PictureURL != headers.PictureURL ||
					(!record.PictureSyncedAt.IsZero() && time.Since(record.PictureSyncedAt) > 24*time.Hour) ||
					(record.PictureSyncedAt.IsZero() && record.PictureURL != "")
				if shouldSync {
					// Only start a sync if one isn't already in flight for this user.
					if _, loaded := pictureSyncInFlight.LoadOrStore(headers.Email, true); !loaded {
						pictureURL := headers.PictureURL
						userEmail := headers.Email
						go func() {
							defer pictureSyncInFlight.Delete(userEmail)
							if err := embyClient.SetProfileImage(context.Background(), embyUserID, pictureURL); err != nil {
								slog.Warn("failed to set profile image",
									"email", userEmail,
									"emby_user_id", embyUserID,
									"error", err,
								)
								return
							}
							if err := database.UpdatePictureURL(userEmail, pictureURL); err != nil {
								slog.Warn("failed to update stored picture URL",
									"email", userEmail,
									"error", err,
								)
							}
						}()
					}
				}
			}

			// Non-blocking: enforce IsDisabled=false and EnableUserPreferenceAccess=false
			// on the user's current policy (preserves admin-configured settings).
			go func() {
				currentPolicy, fetchErr := embyClient.GetUserPolicy(context.Background(), embyUserID)
				if fetchErr != nil {
					slog.Warn("failed to fetch current user policy",
						"email", headers.Email,
						"emby_user_id", embyUserID,
						"error", fetchErr,
					)
					return
				}
				var policy map[string]interface{}
				if json.Unmarshal(currentPolicy, &policy) != nil {
					return
				}
				policy["IsDisabled"] = false
				policy["EnableUserPreferenceAccess"] = false
				updatedPolicy, marshalErr := json.Marshal(policy)
				if marshalErr != nil {
					return
				}
				if err := embyClient.UpdatePolicyRaw(context.Background(), embyUserID, updatedPolicy); err != nil {
					slog.Warn("failed to enforce user policy",
						"email", headers.Email,
						"emby_user_id", embyUserID,
						"error", err,
					)
				}
			}()

			// Store auth session in context for downstream handlers.
			ctx = handler.WithAuthSession(ctx, authResult.AccessToken, authResult.User.ID, authResult.ServerID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
