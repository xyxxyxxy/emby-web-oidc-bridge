package handler

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
)

const accountPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Emby Account</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; }
        .credentials { background: #f5f5f5; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; }
        .credentials dt { font-weight: bold; margin-top: 1rem; }
        .credentials dd { margin: 0.25rem 0 0 0; font-family: monospace; font-size: 1.1rem; }
        .note { color: #666; font-size: 0.9rem; margin-top: 1.5rem; }
    </style>
</head>
<body>
    <h1>Your Emby Credentials</h1>
    <div class="credentials">
        <dl>
            <dt>Username</dt>
            <dd>{{.Email}}</dd>
            <dt>Password</dt>
            <dd>{{.Password}}</dd>
        </dl>
    </div>
    <p class="note">Use these credentials to sign in on Emby TV and mobile apps where OIDC login is not available.</p>
</body>
</html>`

var accountTmpl = template.Must(template.New("account").Parse(accountPageTemplate))

// Account returns an http.HandlerFunc for the /account endpoint.
// Renders an HTML page showing the user's email and password.
func Account(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-Forwarded-Email")
		if email == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		record, err := database.FindUser(email)
		if err != nil {
			slog.Error("account page: database error", "email", email, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if record == nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err = accountTmpl.Execute(w, struct {
			Email    string
			Password string
		}{
			Email:    record.Email,
			Password: record.Password,
		})
		if err != nil {
			slog.Error("account page: template render error", "email", email, "error", err)
		}
	}
}
