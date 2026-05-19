package config

import (
	"net"
	"os"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func clearEnv() {
	os.Unsetenv("EMBY_API_URL")
	os.Unsetenv("EMBY_API_KEY")
	os.Unsetenv("TEMPLATE_USER_NAME")
	os.Unsetenv("TRUSTED_PROXIES")
	os.Unsetenv("BRIDGE_PORT")
	os.Unsetenv("DATABASE_PATH")
}

func setRequiredEnv() {
	os.Setenv("EMBY_API_URL", "http://emby:8096/emby")
	os.Setenv("EMBY_API_KEY", "test-api-key")
	os.Setenv("TEMPLATE_USER_NAME", "template")
	os.Setenv("TRUSTED_PROXIES", "192.168.1.0/24")
}

func TestLoad_AllRequiredSet(t *testing.T) {
	clearEnv()
	setRequiredEnv()
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.EmbyAPIURL != "http://emby:8096/emby" {
		t.Errorf("EmbyAPIURL = %q, want %q", cfg.EmbyAPIURL, "http://emby:8096/emby")
	}
	if cfg.EmbyAPIKey != "test-api-key" {
		t.Errorf("EmbyAPIKey = %q, want %q", cfg.EmbyAPIKey, "test-api-key")
	}
	if cfg.TemplateUserName != "template" {
		t.Errorf("TemplateUserName = %q, want %q", cfg.TemplateUserName, "template")
	}
	if cfg.BridgePort != 8080 {
		t.Errorf("BridgePort = %d, want %d", cfg.BridgePort, 8080)
	}
	if cfg.DatabasePath != "/data/users.db" {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, "/data/users.db")
	}
	if len(cfg.TrustedProxies) != 1 {
		t.Fatalf("TrustedProxies length = %d, want 1", len(cfg.TrustedProxies))
	}
}

func TestLoad_MissingEmbyAPIURL(t *testing.T) {
	clearEnv()
	os.Setenv("EMBY_API_KEY", "key")
	os.Setenv("TEMPLATE_USER_NAME", "template")
	os.Setenv("TRUSTED_PROXIES", "10.0.0.1")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "required environment variable EMBY_API_URL is not set" {
		t.Errorf("error = %q, want mention of EMBY_API_URL", got)
	}
}

func TestLoad_MissingEmbyAPIKey(t *testing.T) {
	clearEnv()
	os.Setenv("EMBY_API_URL", "http://emby:8096/emby")
	os.Setenv("TEMPLATE_USER_NAME", "template")
	os.Setenv("TRUSTED_PROXIES", "10.0.0.1")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "required environment variable EMBY_API_KEY is not set" {
		t.Errorf("error = %q, want mention of EMBY_API_KEY", got)
	}
}

func TestLoad_MissingTemplateUserName(t *testing.T) {
	clearEnv()
	os.Setenv("EMBY_API_URL", "http://emby:8096/emby")
	os.Setenv("EMBY_API_KEY", "key")
	os.Setenv("TRUSTED_PROXIES", "10.0.0.1")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "required environment variable TEMPLATE_USER_NAME is not set" {
		t.Errorf("error = %q, want mention of TEMPLATE_USER_NAME", got)
	}
}

func TestLoad_MissingTrustedProxies(t *testing.T) {
	clearEnv()
	os.Setenv("EMBY_API_URL", "http://emby:8096/emby")
	os.Setenv("EMBY_API_KEY", "key")
	os.Setenv("TEMPLATE_USER_NAME", "template")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "required environment variable TRUSTED_PROXIES is not set" {
		t.Errorf("error = %q, want mention of TRUSTED_PROXIES", got)
	}
}

func TestLoad_CustomPort(t *testing.T) {
	clearEnv()
	setRequiredEnv()
	os.Setenv("BRIDGE_PORT", "9090")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BridgePort != 9090 {
		t.Errorf("BridgePort = %d, want 9090", cfg.BridgePort)
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	clearEnv()
	setRequiredEnv()
	os.Setenv("BRIDGE_PORT", "not-a-number")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid port, got nil")
	}
}

func TestLoad_CustomDatabasePath(t *testing.T) {
	clearEnv()
	setRequiredEnv()
	os.Setenv("DATABASE_PATH", "/tmp/test.db")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DatabasePath != "/tmp/test.db" {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, "/tmp/test.db")
	}
}

func TestParseTrustedProxies_SingleIP(t *testing.T) {
	networks, err := ParseTrustedProxies("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(networks))
	}
	if !networks[0].IP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("IP = %v, want 192.168.1.1", networks[0].IP)
	}
	ones, bits := networks[0].Mask.Size()
	if ones != 32 || bits != 32 {
		t.Errorf("mask = /%d (of %d), want /32", ones, bits)
	}
}

func TestParseTrustedProxies_CIDR(t *testing.T) {
	networks, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(networks))
	}
	ones, _ := networks[0].Mask.Size()
	if ones != 8 {
		t.Errorf("mask = /%d, want /8", ones)
	}
}

func TestParseTrustedProxies_Multiple(t *testing.T) {
	networks, err := ParseTrustedProxies("192.168.1.1, 10.0.0.0/16, 172.16.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(networks) != 3 {
		t.Fatalf("got %d networks, want 3", len(networks))
	}
}

func TestParseTrustedProxies_IPv6(t *testing.T) {
	networks, err := ParseTrustedProxies("::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(networks))
	}
	ones, bits := networks[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Errorf("mask = /%d (of %d), want /128", ones, bits)
	}
}

func TestParseTrustedProxies_InvalidEntry(t *testing.T) {
	_, err := ParseTrustedProxies("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid entry, got nil")
	}
}

func TestParseTrustedProxies_EmptyString(t *testing.T) {
	_, err := ParseTrustedProxies("")
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

func TestParseTrustedProxies_ContainsCheck(t *testing.T) {
	networks, err := ParseTrustedProxies("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// IP within the subnet should be contained
	if !networks[0].Contains(net.ParseIP("192.168.1.100")) {
		t.Error("expected 192.168.1.100 to be in 192.168.1.0/24")
	}

	// IP outside the subnet should not be contained
	if networks[0].Contains(net.ParseIP("192.168.2.1")) {
		t.Error("expected 192.168.2.1 to NOT be in 192.168.1.0/24")
	}
}

// Feature: emby-auth-bridge, Property 6: Missing config error reporting
// **Validates: Requirements 11.7**
func TestMissingConfigErrorReporting(t *testing.T) {
	requiredVars := []string{
		"EMBY_API_URL",
		"EMBY_API_KEY",
		"TEMPLATE_USER_NAME",
		"TRUSTED_PROXIES",
	}

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random non-empty subset of required vars to unset
		// We pick a random bitmask (1 to 15) to select which vars to unset
		bitmask := rapid.IntRange(1, (1<<len(requiredVars))-1).Draw(t, "missingVarsBitmask")

		// Clear all env vars first
		for _, v := range requiredVars {
			os.Unsetenv(v)
		}
		os.Unsetenv("BRIDGE_PORT")
		os.Unsetenv("DATABASE_PATH")

		// Set all required vars with valid values
		validValues := map[string]string{
			"EMBY_API_URL":       "http://emby:8096/emby",
			"EMBY_API_KEY":       "test-key-123",
			"TEMPLATE_USER_NAME": "template",
			"TRUSTED_PROXIES":    "192.168.1.0/24",
		}
		for _, v := range requiredVars {
			os.Setenv(v, validValues[v])
		}

		// Unset the vars selected by the bitmask
		var missingVars []string
		for i, v := range requiredVars {
			if bitmask&(1<<i) != 0 {
				os.Unsetenv(v)
				missingVars = append(missingVars, v)
			}
		}

		// Call Load() — it should fail
		_, err := Load()
		if err == nil {
			t.Fatalf("expected error when missing vars %v, got nil", missingVars)
		}

		// The error message must name at least one of the missing variables.
		// Since Load() checks vars sequentially, it will report the first missing one.
		errMsg := err.Error()
		foundNamedVar := false
		for _, v := range missingVars {
			if strings.Contains(errMsg, v) {
				foundNamedVar = true
				break
			}
		}

		if !foundNamedVar {
			t.Fatalf("error %q does not name any of the missing variables %v", errMsg, missingVars)
		}

		// Clean up
		for _, v := range requiredVars {
			os.Unsetenv(v)
		}
	})
}
