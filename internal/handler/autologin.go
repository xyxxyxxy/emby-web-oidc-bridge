package handler

import (
	"html/template"
	"log/slog"
	"net/http"
)

const autoLoginTemplate = `<!DOCTYPE html>
<html>
<head><title>Logging in...</title></head>
<body>
<script>
(function() {
    var credentials = {
        "Servers": [{
            "Id": "{{.ServerID}}",
            "AccessToken": "{{.Token}}",
            "UserId": "{{.UserID}}"
        }]
    };
    localStorage.setItem("jellyfin_credentials", JSON.stringify(credentials));
    // Emby also uses this key in some versions
    localStorage.setItem("emby_credentials", JSON.stringify(credentials));
    window.location.replace("/web/index.html");
})();
</script>
<noscript><p>JavaScript is required. <a href="/web/index.html">Continue to Emby</a></p></noscript>
</body>
</html>`

var autoLoginTmpl = template.Must(template.New("autologin").Parse(autoLoginTemplate))

// AutoLogin returns an http.HandlerFunc that serves a page which injects
// the Emby auth credentials into localStorage and redirects to the web UI.
// This enables seamless auto-login without the user seeing the Emby login page.
func AutoLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := AuthTokenFromContext(r.Context())
		userID := AuthUserIDFromContext(r.Context())
		serverID := AuthServerIDFromContext(r.Context())

		if token == "" || userID == "" || serverID == "" {
			slog.Error("autologin: missing auth session data",
				"has_token", token != "",
				"has_user_id", userID != "",
				"has_server_id", serverID != "",
			)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		err := autoLoginTmpl.Execute(w, struct {
			Token    string
			UserID   string
			ServerID string
		}{
			Token:    token,
			UserID:   userID,
			ServerID: serverID,
		})
		if err != nil {
			slog.Error("autologin: template render error", "error", err)
		}
	}
}
