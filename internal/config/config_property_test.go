package config_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/config"
)

func clearEnv() {
	_ = os.Unsetenv("EMBY_API_URL")
	_ = os.Unsetenv("EMBY_API_KEY")
	_ = os.Unsetenv("TEMPLATE_USER_NAME")
	_ = os.Unsetenv("TRUSTED_PROXIES")
	_ = os.Unsetenv("BRIDGE_PORT")
	_ = os.Unsetenv("DATABASE_PATH")
	_ = os.Unsetenv("OIDC_ISSUER_URL")
	_ = os.Unsetenv("EMBY_WATCHPARTY_URL")
}

func setRequiredEnv() {
	_ = os.Setenv("EMBY_API_URL", "http://emby:8096/emby")
	_ = os.Setenv("EMBY_API_KEY", "test-api-key")
	_ = os.Setenv("TEMPLATE_USER_NAME", "template")
	_ = os.Setenv("TRUSTED_PROXIES", "192.168.1.0/24")
}

// genValidURL generates a random valid URL with scheme and host.
func genValidURL(t *rapid.T) string {
	schemes := []string{"http", "https"}
	scheme := schemes[rapid.IntRange(0, 1).Draw(t, "schemeIdx")]
	host := rapid.StringMatching(`[a-z][a-z0-9]{1,10}\.[a-z]{2,4}`).Draw(t, "host")

	u := scheme + "://" + host

	if rapid.Bool().Draw(t, "hasPort") {
		port := rapid.IntRange(1, 65535).Draw(t, "port")
		u += fmt.Sprintf(":%d", port)
	}

	if rapid.Bool().Draw(t, "hasPath") {
		path := rapid.StringMatching(`/[a-z0-9]{1,10}(/[a-z0-9]{1,10})?`).Draw(t, "path")
		u += path
	}

	return u
}

// genWhitespace generates random whitespace characters (spaces, tabs, newlines).
func genWhitespace(t *rapid.T) string {
	n := rapid.IntRange(0, 5).Draw(t, "wsLen")
	wsChars := []rune{' ', '\t', '\n', '\r'}
	result := make([]rune, n)
	for i := range result {
		result[i] = wsChars[rapid.IntRange(0, len(wsChars)-1).Draw(t, "wsChar")]
	}
	return string(result)
}

// Feature: emby-watchparty-support, Property 1: Watchparty config enable/disable follows trimmed URL validity
// **Validates: Requirements 1.2, 1.3**
func TestWatchpartyConfigEnableDisable(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		clearEnv()
		setRequiredEnv()
		defer clearEnv()

		// Decide whether to generate a valid URL or whitespace-only/empty string
		useValidURL := rapid.Bool().Draw(t, "useValidURL")

		if useValidURL {
			// Generate a valid URL with optional whitespace padding
			validURL := genValidURL(t)
			prefix := genWhitespace(t)
			suffix := genWhitespace(t)
			envValue := prefix + validURL + suffix

			_ = os.Setenv("EMBY_WATCHPARTY_URL", envValue)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("unexpected error for valid URL %q: %v", envValue, err)
				return
			}

			if !cfg.WatchpartyEnabled() {
				t.Fatalf("WatchpartyEnabled() = false, want true for URL %q", envValue)
				return
			}

			if cfg.WatchpartyURL != validURL {
				t.Fatalf("WatchpartyURL = %q, want %q (trimmed)", cfg.WatchpartyURL, validURL)
			}
		} else {
			// Generate whitespace-only or empty string
			wsOnly := genWhitespace(t)
			_ = os.Setenv("EMBY_WATCHPARTY_URL", wsOnly)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("unexpected error for whitespace-only %q: %v", wsOnly, err)
				return
			}

			if cfg.WatchpartyEnabled() {
				t.Fatalf("WatchpartyEnabled() = true, want false for whitespace-only %q", wsOnly)
				return
			}

			if cfg.WatchpartyURL != "" {
				t.Fatalf("WatchpartyURL = %q, want empty for whitespace-only input", cfg.WatchpartyURL)
			}
		}
	})
}

// Feature: emby-watchparty-support, Property 2: Invalid URL produces configuration error
// **Validates: Requirements 1.4**
func TestWatchpartyInvalidURLProducesError(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		clearEnv()
		setRequiredEnv()
		defer clearEnv()

		// Generate a non-empty string that is NOT a valid URL.
		strategy := rapid.IntRange(0, 2).Draw(t, "strategy")

		var invalidURL string
		switch strategy {
		case 0:
			// No scheme at all: random non-empty string that won't parse as valid URL
			invalidURL = rapid.StringMatching(`[a-zA-Z0-9._-]{1,20}`).Draw(t, "noScheme")
			// Remove any accidental "://" occurrences
			invalidURL = strings.ReplaceAll(invalidURL, "://", "")
			if strings.TrimSpace(invalidURL) == "" {
				invalidURL = "notaurl"
			}
		case 1:
			// Scheme present but no host (e.g., "http://")
			schemes := []string{"http", "https"}
			scheme := schemes[rapid.IntRange(0, 1).Draw(t, "schemeIdx")]
			invalidURL = scheme + "://"
		case 2:
			// Relative path only (no scheme, no host)
			invalidURL = "/" + rapid.StringMatching(`[a-z0-9]{1,15}`).Draw(t, "relPath")
		}

		_ = os.Setenv("EMBY_WATCHPARTY_URL", invalidURL)

		_, err := config.Load()
		if err == nil {
			t.Fatalf("expected error for invalid URL %q, got nil", invalidURL)
			return
		}

		if !strings.Contains(err.Error(), "EMBY_WATCHPARTY_URL") {
			t.Fatalf("error %q does not mention EMBY_WATCHPARTY_URL", err.Error())
		}
	})
}
