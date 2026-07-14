package handler

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
)

const accountPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Emby Account</title>
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 2rem auto; padding: 0 1rem; background: #1a1a1a; color: #e0e0e0; }
        h1 { color: #fff; }
        .credentials { background: #2a2a2a; padding: 1.5rem; border-radius: 8px; margin: 1rem 0; border: 1px solid #3a3a3a; }
        .credentials dt { font-weight: bold; margin-top: 1rem; color: #aaa; }
        .credentials dd { margin: 0.25rem 0 0 0; font-family: monospace; font-size: 1.1rem; color: #fff; display: flex; align-items: center; gap: 0.5rem; }
        .copy-btn { background: #3a3a3a; border: 1px solid #555; color: #ccc; padding: 0.25rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem; }
        .copy-btn:hover { background: #4a4a4a; color: #fff; }
        .copy-btn.copied { background: #2e7d32; border-color: #4caf50; color: #fff; }
        .note { color: #888; font-size: 0.9rem; margin-top: 1.5rem; }
    </style>
</head>
<body>
    <h1>Your Emby Credentials</h1>
    <div class="credentials">
        <dl>
            <dt>Username</dt>
            <dd><span id="username">{{.Username}}</span><button class="copy-btn" onclick="copyText('username', this)" aria-label="Copy username">Copy</button></dd>
            <dt>Password</dt>
            <dd><span id="password">{{.Password}}</span><button class="copy-btn" onclick="copyText('password', this)" aria-label="Copy password">Copy</button></dd>
        </dl>
    </div>
    <p class="note">Use these credentials to sign in on Emby TV and mobile apps where OIDC login is not available.</p>
    <script>
    function copyText(id, btn) {
        var text = document.getElementById(id).textContent;
        navigator.clipboard.writeText(text).then(function() {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(function() {
                btn.textContent = 'Copy';
                btn.classList.remove('copied');
            }, 2000);
        });
    }
    </script>
</body>
</html>`

var accountTmpl = template.Must(template.New("account").Parse(accountPageTemplate))

// ExtractSubFromRequest extracts the OIDC sub claim from request headers or JWT.
func ExtractSubFromRequest(r *http.Request) string {
	// Try explicit sub headers first.
	sub := r.Header.Get("X-Forwarded-Sub")
	if sub == "" {
		sub = r.Header.Get("X-Auth-Request-Sub")
	}
	if sub != "" {
		return sub
	}

	// Try extracting from JWT.
	token := ""
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
		token = authHeader[7:]
	}
	if token == "" {
		token = r.Header.Get("X-Forwarded-Access-Token")
		if token == "" {
			token = r.Header.Get("X-Auth-Request-Access-Token")
		}
	}
	if token == "" {
		return ""
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
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
		Sub string `json:"sub"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return ""
	}
	return claims.Sub
}

// ExtractPreferredUsernameFromRequest extracts the OIDC preferred_username from the ID token or headers.
func ExtractPreferredUsernameFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
		if preferredUsername := preferredUsernameFromJWT(authHeader[7:]); preferredUsername != "" {
			return preferredUsername
		}
	}

	preferredUsername := r.Header.Get("X-Forwarded-Preferred-Username")
	if preferredUsername == "" {
		preferredUsername = r.Header.Get("X-Auth-Request-Preferred-Username")
	}
	if preferredUsername != "" {
		return preferredUsername
	}

	return ""
}

func preferredUsernameFromJWT(token string) string {
	if token == "" {
		return ""
	}

	return extractPreferredUsernameClaim(token)
}

func extractPreferredUsernameClaim(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
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
		PreferredUsername string `json:"preferred_username"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return ""
	}
	return claims.PreferredUsername
}

// Account returns an http.HandlerFunc for the /account endpoint.
// Renders an HTML page showing the user's Emby username and password.
func Account(database *db.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := ExtractSubFromRequest(r)
		if sub == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		username := ExtractPreferredUsernameFromRequest(r)
		if username == "" {
			http.Error(w, "Unauthorized: missing preferred_username", http.StatusUnauthorized)
			return
		}

		record, err := database.FindUserBySub(sub)
		if err != nil {
			slog.Error("account page: database error", "sub", sub, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if record == nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		err = accountTmpl.Execute(w, struct {
			Username string
			Password string
		}{
			Username: username,
			Password: record.Password,
		})
		if err != nil {
			slog.Error("account page: template render error", "sub", sub, "error", err)
		}
	}
}
