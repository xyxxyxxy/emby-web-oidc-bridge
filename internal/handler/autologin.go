package handler

import (
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const autoLoginTemplate = `<!DOCTYPE html>
<html>
<head><title>Logging in...</title><style>body{background:#000;}</style></head>
<body>
<script>
(function() {
    var serverId = "{{.ServerID}}";
    var userId = "{{.UserID}}";
    var accessToken = "{{.Token}}";

    var existing = {};
    try { existing = JSON.parse(localStorage.getItem("servercredentials3")) || {}; } catch(e) {}

    var servers = (existing.Servers || []);
    var server = null;
    for (var i = 0; i < servers.length; i++) {
        if (servers[i].Id === serverId) {
            server = servers[i];
            break;
        }
    }
    if (!server) {
        server = {"Id": serverId, "Type": "Server"};
        servers.push(server);
    }

    server.UserId = userId;
    server.DateLastAccessed = Date.now();
    server.LastConnectionMode = 2;
    server.Users = [{"UserId": userId, "AccessToken": accessToken}];

    existing.Servers = servers;
    localStorage.setItem("servercredentials3", JSON.stringify(existing));

    window.location.replace("/web/index.html");
})();
</script>
<noscript><p>JavaScript is required. <a href="/web/index.html">Continue to Emby</a></p></noscript>
</body>
</html>`

var autoLoginTmpl = template.Must(template.New("autologin").Parse(autoLoginTemplate))

// credentialScript generates an inline script that sets Emby credentials in localStorage
// and monitors for login page navigation to redirect back to root for re-authentication.
const credentialScriptTemplate = `<script>
(function() {
    var serverId = "%s";
    var userId = "%s";
    var accessToken = "%s";
    var existing = {};
    try { existing = JSON.parse(localStorage.getItem("servercredentials3")) || {}; } catch(e) {}
    var servers = (existing.Servers || []);
    var server = null;
    for (var i = 0; i < servers.length; i++) {
        if (servers[i].Id === serverId) { server = servers[i]; break; }
    }
    if (!server) { server = {"Id": serverId, "Type": "Server"}; servers.push(server); }
    server.UserId = userId;
    server.DateLastAccessed = Date.now();
    server.LastConnectionMode = 2;
    server.Users = [{"UserId": userId, "AccessToken": accessToken}];
    existing.Servers = servers;
    localStorage.setItem("servercredentials3", JSON.stringify(existing));

    // If the page loaded with a login hash (e.g. after logout), strip it and reload.
    // This lets Emby start fresh and find the credentials we just set.
    var hash = window.location.hash || "";
    if (hash.indexOf("manuallogin") !== -1 || hash.indexOf("selectserver") !== -1) {
        if (!sessionStorage.getItem("embybridge_redirect")) {
            sessionStorage.setItem("embybridge_redirect", "1");
            window.location.href = "/web/index.html";
            return;
        }
    }
    sessionStorage.removeItem("embybridge_redirect");
})();
</script>`

// AutoLogin returns an http.HandlerFunc that serves a page which injects
// the Emby auth credentials into localStorage and redirects to the web UI.
// Used for the root path (/).
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

// InjectCredentials returns an http.HandlerFunc that fetches the real Emby
// web/index.html, injects a credential-setting script before </head>, and
// serves the modified page. This ensures credentials are always fresh on
// every page load without redirects or query param markers.
func InjectCredentials(embyURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := AuthTokenFromContext(r.Context())
		userID := AuthUserIDFromContext(r.Context())
		serverID := AuthServerIDFromContext(r.Context())

		if token == "" || userID == "" || serverID == "" {
			slog.Error("inject-credentials: missing auth session data")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Fetch the real Emby web/index.html.
		targetURL := strings.TrimRight(embyURL, "/") + "/web/index.html"
		resp, err := http.Get(targetURL)
		if err != nil {
			slog.Error("inject-credentials: failed to fetch Emby page", "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("inject-credentials: failed to read Emby page", "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		// Build the credential injection script.
		script := fmt.Sprintf(credentialScriptTemplate, serverID, userID, token)

		// Inject the script right after <head> (before any Emby scripts run).
		html := string(body)
		html = strings.Replace(html, "<head>", "<head>"+script, 1)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(html))
	}
}
