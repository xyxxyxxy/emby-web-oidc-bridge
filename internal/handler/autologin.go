package handler

import (
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
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

// credentialScriptTemplate generates an inline script that sets Emby credentials in localStorage.
// Values are JSON-encoded to prevent XSS via script injection.
const credentialScriptTemplate = `<script>
(function() {
    var serverId = %s;
    var userId = %s;
    var accessToken = %s;
    var existing = {};
    try { existing = JSON.parse(localStorage.getItem("servercredentials3")) || {}; } catch(e) {}
    var servers = (existing.Servers || []);
    var server = null;
    for (var i = 0; i < servers.length; i++) {
        if (servers[i].Id === serverId) { server = servers[i]; break; }
    }
    if (!server) { server = {"Id": serverId, "Type": "Server"}; servers.push(server); }
    var origin = window.location.origin;
    server.ManualAddress = origin;
    server.ManualAddressOnly = true;
    server.Name = "Emby";
    server.UserId = userId;
    server.DateLastAccessed = Date.now();
    server.LastConnectionMode = 2;
    server.Users = [{"UserId": userId, "AccessToken": accessToken}];
    existing.Servers = servers;
    localStorage.setItem("servercredentials3", JSON.stringify(existing));

    var hash = window.location.hash || "";
    if (hash.indexOf("manuallogin") !== -1 || hash.indexOf("selectserver") !== -1 || hash.indexOf("login") !== -1) {
        window.location.replace("/web/index.html");
        return;
    }
})();
</script>`

// jsStringEncode safely encodes a string as a JSON string literal for embedding in JavaScript.
// This prevents XSS by properly escaping quotes, backslashes, and </script> sequences.
func jsStringEncode(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// injectCredentialsClient is an HTTP client with a timeout for fetching the Emby page.
var injectCredentialsClient = &http.Client{
	Timeout: 10 * time.Second,
}

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

		// Fetch the real Emby web/index.html with a timeout.
		targetURL := strings.TrimRight(embyURL, "/") + "/web/index.html"
		resp, err := injectCredentialsClient.Get(targetURL)
		if err != nil {
			slog.Error("inject-credentials: failed to fetch Emby page", "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("inject-credentials: failed to read Emby page", "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		// Build the credential injection script with JSON-encoded values (XSS-safe).
		script := strings.NewReplacer(
			"%s", "", // Clear the template — we'll use Sprintf with safe values.
		).Replace("")
		_ = script
		safeScript := buildCredentialScript(serverID, userID, token)

		// Inject the script right after <head> (before any Emby scripts run).
		html := string(body)
		html = strings.Replace(html, "<head>", "<head>"+safeScript, 1)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(html))
	}
}

// buildCredentialScript generates the credential injection script with safely encoded values.
func buildCredentialScript(serverID, userID, token string) string {
	return strings.Replace(
		strings.Replace(
			strings.Replace(credentialScriptTemplate, "%s", jsStringEncode(serverID), 1),
			"%s", jsStringEncode(userID), 1),
		"%s", jsStringEncode(token), 1)
}

