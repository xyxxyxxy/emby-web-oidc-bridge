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

// sessionCache stores cached auth sessions per OIDC sub to avoid
// re-authenticating with Emby on every request.
// Key: oidc_sub (string), Value: *cachedSession
var sessionCache sync.Map

type cachedSession struct {
	accessToken string
	userID      string
	serverID    string
	embyUserID  string
	expiresAt   time.Time
}

// sessionCacheTTL is how long a cached session is valid before re-authentication.
const sessionCacheTTL = 1 * time.Hour

// clearSessionCache removes all entries from the session cache.
// This is intended for use in tests to ensure isolation between test cases.
func clearSessionCache() {
	sessionCache.Range(func(key, value interface{}) bool {
		sessionCache.Delete(key)
		return true
	})
}

// InvalidateSession removes the cached session for the given OIDC sub.
// This should be called when Emby reports a session has ended (e.g. logout)
// to prevent the bridge from reusing a stale/invalid access token.
func InvalidateSession(sub string) {
	sessionCache.Delete(sub)
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

// extractClaimsFromJWT decodes the payload of a JWT token (without signature verification)
// and extracts the "sub", "preferred_username", "name", "email", and "picture" claims.
// Signature verification is not needed because the token was already validated by oauth2-proxy.
func extractClaimsFromJWT(token string) (sub, preferredUsername, name, email, picture string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
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
		return
	}
	var claims struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		Picture           string `json:"picture"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return
	}
	return claims.Sub, claims.PreferredUsername, claims.Name, claims.Email, claims.Picture
}

// oidcClient is an HTTP client with a timeout for OIDC userinfo requests.
var oidcClient = &http.Client{
	Timeout: 10 * time.Second,
}

// AuthTokenFromContext retrieves the Emby auth token from the request context.
// This delegates to handler.AuthTokenFromContext to ensure the same context key is used.
func AuthTokenFromContext(ctx context.Context) string {
	return handler.AuthTokenFromContext(ctx)
}

// OIDCHeaders holds extracted OIDC session headers.
type OIDCHeaders struct {
	Sub               string
	PreferredUsername string
	Name              string
	Email             string
	PictureURL        string
}

// embyUsername returns the OIDC preferred_username claim, used as the Emby username.
func (h *OIDCHeaders) embyUsername() string {
	return h.PreferredUsername
}

// displayName returns the best display name for logging/DB storage.
// This is preferred_username > name (whichever is set first).
func (h *OIDCHeaders) displayName() string {
	if h.PreferredUsername != "" {
		return h.PreferredUsername
	}
	return h.Name
}

// Auth returns middleware that extracts headers, provisions users, and authenticates with Emby.
// Users are identified by their OIDC sub (subject) claim. The Emby account username is set to
// the OIDC preferred_username claim. Name and email changes are synced automatically.
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
			pictureURL := r.Header.Get("X-Forwarded-Picture")
			if pictureURL == "" {
				pictureURL = r.Header.Get("X-Auth-Request-Picture")
			}

			// Extract sub from X-Forwarded-Sub / X-Auth-Request-Sub headers first.
			sub := r.Header.Get("X-Forwarded-Sub")
			if sub == "" {
				sub = r.Header.Get("X-Auth-Request-Sub")
			}

			// Try to extract claims from the JWT ID token.
			var jwtSub, jwtPreferredUsername, jwtName, jwtEmail, jwtPicture string
			idToken := ""
			authHeader := r.Header.Get("Authorization")
			if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
				idToken = authHeader[7:]
			}
			if idToken == "" {
				idToken = r.Header.Get("X-Forwarded-Access-Token")
				if idToken == "" {
					idToken = r.Header.Get("X-Auth-Request-Access-Token")
				}
			}
			if idToken != "" {
				jwtSub, jwtPreferredUsername, jwtName, jwtEmail, jwtPicture = extractClaimsFromJWT(idToken)
			}

			// Preferred username: from headers or JWT.
			preferredUsername := r.Header.Get("X-Forwarded-Preferred-Username")
			if preferredUsername == "" {
				preferredUsername = r.Header.Get("X-Auth-Request-Preferred-Username")
			}
			if preferredUsername == "" {
				preferredUsername = jwtPreferredUsername
			}

			// Display name: from JWT "name" claim or X-Forwarded-User header.
			// oauth2-proxy sets X-Forwarded-User to the "user" claim which defaults
			// to "sub" (a UUID), not the human-readable display name.
			displayName := jwtName
			if displayName == "" {
				displayName = r.Header.Get("X-Forwarded-User")
				if displayName == "" {
					displayName = r.Header.Get("X-Auth-Request-User")
				}
			}

			// Fill in missing values from JWT claims.
			if sub == "" {
				sub = jwtSub
			}
			if email == "" {
				email = jwtEmail
			}
			if pictureURL == "" && jwtPicture != "" {
				pictureURL = jwtPicture
			}

			// If displayName equals sub, it's likely oauth2-proxy sending the sub
			// as X-Forwarded-User — don't use it as a display name.
			if displayName == sub {
				displayName = ""
			}
			// Same for preferredUsername — shouldn't be the sub.
			if preferredUsername == sub {
				preferredUsername = ""
			}

			headers := OIDCHeaders{
				Sub:               sub,
				PreferredUsername: preferredUsername,
				Name:              displayName,
				Email:             email,
				PictureURL:        pictureURL,
			}

			// Sub is required — it's the stable user identifier.
			if headers.Sub == "" {
				slog.Warn("missing OIDC sub claim",
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized: missing sub claim", http.StatusUnauthorized)
				return
			}

			// preferred_username is required for the Emby username.
			if headers.embyUsername() == "" {
				slog.Warn("missing preferred_username from OIDC",
					"sub", headers.Sub,
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Unauthorized: missing preferred_username", http.StatusUnauthorized)
				return
			}

			// If no picture URL from headers/JWT, try fetching from OIDC userinfo endpoint.
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
						resp, err := oidcClient.Do(req)
						if err == nil {
							defer func() { _ = resp.Body.Close() }()
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

			// Check session cache — if we have a valid cached session, skip everything.
			if cached, ok := sessionCache.Load(headers.Sub); ok {
				session := cached.(*cachedSession)
				if time.Now().Before(session.expiresAt) {
					ctx = handler.WithAuthUsername(ctx, headers.embyUsername())
					ctx = handler.WithAuthSub(ctx, headers.Sub)
					ctx = handler.WithAuthSession(ctx, session.accessToken, session.userID, session.serverID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Session expired — delete and continue with fresh auth.
				sessionCache.Delete(headers.Sub)
			}

			slog.Info("processing authentication",
				"sub", headers.Sub,
				"name", headers.Name,
				"email", headers.Email,
				"picture_url", headers.PictureURL,
			)

			// Lookup user in database by OIDC sub.
			record, err := database.FindUserBySub(headers.Sub)
			if err != nil {
				slog.Error("database lookup failed",
					"sub", headers.Sub,
					"error", err,
				)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			var userPassword string
			var embyUserID string
			embyUsername := headers.embyUsername()

			if record != nil {
				// User exists in DB — use stored password.
				userPassword = record.Password
				embyUserID = record.EmbyUserID
				slog.Info("user found in database",
					"sub", headers.Sub,
					"emby_user_id", embyUserID,
				)

				// Authenticate with the linked Emby account's actual username, which may
				// differ from OIDC preferred_username (e.g. after a username mapping change).
				if embyUser, getErr := embyClient.GetUser(ctx, embyUserID); getErr == nil {
					embyUsername = embyUser.Name
				}

				desiredUsername := headers.embyUsername()

				// Sync name/email changes from OIDC to the bridge DB.
				nameChanged := headers.displayName() != record.Name || headers.Email != record.Email
				if nameChanged {
					if err := database.UpdateUserIdentity(headers.Sub, headers.displayName(), headers.Email); err != nil {
						slog.Error("failed to update user identity in database",
							"sub", headers.Sub,
							"error", err,
						)
						// Non-fatal: continue with auth.
					}
				}

				// Sync Emby username to preferred_username when possible.
				if desiredUsername != "" && desiredUsername != embyUsername {
					newName := desiredUsername
					existingUser, lookupErr := embyClient.FindUserByName(ctx, newName)
					if lookupErr == nil && existingUser != nil && existingUser.ID != embyUserID {
						// Name is taken — keep the current Emby username.
						newName = embyUsername
					}

					if newName != embyUsername {
						slog.Info("syncing username change to Emby",
							"sub", headers.Sub,
							"old_name", embyUsername,
							"new_name", newName,
						)
						if err := embyClient.UpdateUserName(ctx, embyUserID, newName); err != nil {
							slog.Error("failed to rename user in Emby",
								"sub", headers.Sub,
								"emby_user_id", embyUserID,
								"new_name", newName,
								"error", err,
							)
							// Non-fatal: continue with auth using current name.
						} else {
							embyUsername = newName
						}
					}
				}
			} else {
				// User not in DB — provision with the OIDC preferred_username.
				// If that username already exists in Emby, adopt that user.
				existingUser, err := embyClient.FindUserByName(ctx, embyUsername)
				if err != nil {
					slog.Error("emby user lookup failed",
						"sub", headers.Sub,
						"username", embyUsername,
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
						"sub", headers.Sub,
						"username", embyUsername,
						"emby_user_id", embyUserID,
					)

					// Update password in Emby.
					if err := embyClient.UpdatePassword(ctx, embyUserID, userPassword); err != nil {
						slog.Error("failed to update password for adopted user",
							"sub", headers.Sub,
							"emby_user_id", embyUserID,
							"error", err,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
				} else {
					// User doesn't exist anywhere — create new user.
					slog.Info("provisioning new user",
						"sub", headers.Sub,
						"username", embyUsername,
					)

					newUser, createErr := embyClient.CreateUser(ctx, embyUsername, templateUserID)
					if createErr != nil {
						slog.Error("failed to create user in Emby",
							"sub", headers.Sub,
							"username", embyUsername,
							"error", createErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					embyUserID = newUser.ID

					// Set password.
					if err := embyClient.UpdatePassword(ctx, embyUserID, userPassword); err != nil {
						slog.Error("failed to set password for new user",
							"sub", headers.Sub,
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
							"sub", headers.Sub,
							"error", polBuildErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
					if err := embyClient.UpdatePolicyRaw(ctx, embyUserID, policyJSON); err != nil {
						slog.Error("failed to update policy for new user",
							"sub", headers.Sub,
							"emby_user_id", embyUserID,
							"error", err,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}
				}

				// Store user in database.
				if err := database.InsertUser(headers.Sub, headers.displayName(), headers.Email, embyUserID, userPassword); err != nil {
					slog.Error("failed to store user in database",
						"sub", headers.Sub,
						"emby_user_id", embyUserID,
						"error", err,
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				slog.Info("user provisioned successfully",
					"sub", headers.Sub,
					"username", embyUsername,
					"emby_user_id", embyUserID,
				)
			}

			// Authenticate with Emby using the current Emby username.
			authResult, err := embyClient.AuthenticateByName(ctx, embyUsername, userPassword)
			if err != nil {
				// If user was in DB but auth failed, they may have been deleted from Emby.
				// Check if user still exists and re-provision if needed.
				if record != nil {
					staleEmbyUserID := embyUserID

					slog.Warn("authentication failed for existing DB user, checking if user was deleted from Emby",
						"sub", headers.Sub,
						"emby_user_id", staleEmbyUserID,
						"error", err,
					)

					// Delete stale cache entry.
					sessionCache.Delete(headers.Sub)

					// Delete stale DB record.
					if delErr := database.DeleteUser(headers.Sub); delErr != nil {
						slog.Error("failed to delete stale user record",
							"sub", headers.Sub,
							"error", delErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Prefer the previously linked Emby account over creating a duplicate.
					var existingUser *emby.User
					if staleEmbyUserID != "" {
						linkedUser, getErr := embyClient.GetUser(ctx, staleEmbyUserID)
						if getErr == nil {
							existingUser = linkedUser
							embyUsername = linkedUser.Name
						}
					}
					if existingUser == nil {
						var lookupErr error
						existingUser, lookupErr = embyClient.FindUserByName(ctx, headers.embyUsername())
						if lookupErr != nil {
							slog.Error("emby user lookup failed during re-provision check",
								"sub", headers.Sub,
								"error", lookupErr,
							)
							http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
							return
						}
						if existingUser != nil {
							embyUsername = existingUser.Name
						}
					}

					// Generate a new password and re-provision.
					userPassword = password.Generate()

					if existingUser != nil {
						// User still exists in Emby — update password only; preserve existing policy.
						embyUserID = existingUser.ID
						slog.Warn("re-adopting Emby user after auth failure",
							"sub", headers.Sub,
							"emby_user_id", embyUserID,
						)
						if pwErr := embyClient.UpdatePassword(ctx, embyUserID, userPassword); pwErr != nil {
							slog.Error("failed to update password during re-provision",
								"sub", headers.Sub,
								"error", pwErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
					} else {
						// User was deleted from Emby — create fresh.
						slog.Warn("user deleted from Emby, re-provisioning",
							"sub", headers.Sub,
							"username", embyUsername,
						)
						newUser, createErr := embyClient.CreateUser(ctx, embyUsername, templateUserID)
						if createErr != nil {
							slog.Error("failed to re-create user in Emby",
								"sub", headers.Sub,
								"error", createErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						embyUserID = newUser.ID

						if pwErr := embyClient.UpdatePassword(ctx, embyUserID, userPassword); pwErr != nil {
							slog.Error("failed to set password for re-created user",
								"sub", headers.Sub,
								"error", pwErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						policyJSON, polBuildErr := buildUserPolicy(templatePolicy)
						if polBuildErr != nil {
							slog.Error("failed to build user policy for re-created user",
								"sub", headers.Sub,
								"error", polBuildErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						if polErr := embyClient.UpdatePolicyRaw(ctx, embyUserID, policyJSON); polErr != nil {
							slog.Error("failed to update policy for re-created user",
								"sub", headers.Sub,
								"error", polErr,
							)
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
					}

					// Store new record in DB.
					if insErr := database.InsertUser(headers.Sub, headers.displayName(), headers.Email, embyUserID, userPassword); insErr != nil {
						slog.Error("failed to store re-provisioned user in database",
							"sub", headers.Sub,
							"error", insErr,
						)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						return
					}

					// Retry authentication.
					authResult, err = embyClient.AuthenticateByName(ctx, embyUsername, userPassword)
					if err != nil {
						slog.Error("authentication still failed after re-provision",
							"sub", headers.Sub,
							"error", err,
						)
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}

					slog.Info("user re-provisioned and authenticated successfully",
						"sub", headers.Sub,
						"emby_user_id", embyUserID,
					)
				} else {
					slog.Error("authentication with Emby failed",
						"sub", headers.Sub,
						"error", err,
					)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			slog.Info("authenticated with Emby",
				"sub", headers.Sub,
				"emby_user_id", authResult.User.ID,
			)

			// Store session in cache for subsequent requests.
			sessionCache.Store(headers.Sub, &cachedSession{
				accessToken: authResult.AccessToken,
				userID:      authResult.User.ID,
				serverID:    authResult.ServerID,
				embyUserID:  embyUserID,
				expiresAt:   time.Now().Add(sessionCacheTTL),
			})

			// Non-blocking: sync profile image when URL has changed (or on first provisioning).
			// Uses pictureSyncInFlight to prevent concurrent syncs for the same user.
			if headers.PictureURL != "" {
				shouldSync := record == nil || record.PictureURL != headers.PictureURL ||
					(!record.PictureSyncedAt.IsZero() && time.Since(record.PictureSyncedAt) > 24*time.Hour) ||
					(record.PictureSyncedAt.IsZero() && record.PictureURL != "")
				if shouldSync {
					// Only start a sync if one isn't already in flight for this user.
					if _, loaded := pictureSyncInFlight.LoadOrStore(headers.Sub, true); !loaded {
						pictureURL := headers.PictureURL
						userSub := headers.Sub
						go func() {
							defer pictureSyncInFlight.Delete(userSub)
							bgCtx, bgCancel := context.WithTimeout(context.Background(), 30*time.Second)
							defer bgCancel()
							if err := embyClient.SetProfileImage(bgCtx, embyUserID, pictureURL); err != nil {
								slog.Warn("failed to set profile image",
									"sub", userSub,
									"emby_user_id", embyUserID,
									"error", err,
								)
								return
							}
							if err := database.UpdatePictureURL(userSub, pictureURL); err != nil {
								slog.Warn("failed to update stored picture URL",
									"sub", userSub,
									"error", err,
								)
							}
						}()
					}
				}
			}

			// Non-blocking: enforce IsDisabled=false and EnableUserPreferenceAccess=false
			// on the user's current policy. Only updates if the values differ to avoid
			// spamming Emby logs with unnecessary policy update notifications.
			go func() {
				bgCtx, bgCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer bgCancel()
				currentPolicy, fetchErr := embyClient.GetUserPolicy(bgCtx, embyUserID)
				if fetchErr != nil {
					slog.Warn("failed to fetch current user policy",
						"sub", headers.Sub,
						"emby_user_id", embyUserID,
						"error", fetchErr,
					)
					return
				}
				var policy map[string]interface{}
				if json.Unmarshal(currentPolicy, &policy) != nil {
					return
				}

				// Check whether policy changes are actually needed.
				isDisabled, _ := policy["IsDisabled"].(bool)
				enablePrefAccess, _ := policy["EnableUserPreferenceAccess"].(bool)
				if !isDisabled && !enablePrefAccess {
					// Policy already matches desired state — skip update.
					return
				}

				policy["IsDisabled"] = false
				policy["EnableUserPreferenceAccess"] = false
				updatedPolicy, marshalErr := json.Marshal(policy)
				if marshalErr != nil {
					return
				}
				if err := embyClient.UpdatePolicyRaw(bgCtx, embyUserID, updatedPolicy); err != nil {
					slog.Warn("failed to enforce user policy",
						"sub", headers.Sub,
						"emby_user_id", embyUserID,
						"error", err,
					)
				}
			}()

			// Store auth session in context for downstream handlers.
			ctx = handler.WithAuthUsername(ctx, headers.embyUsername())
			ctx = handler.WithAuthSub(ctx, headers.Sub)
			ctx = handler.WithAuthSession(ctx, authResult.AccessToken, authResult.User.ID, authResult.ServerID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
