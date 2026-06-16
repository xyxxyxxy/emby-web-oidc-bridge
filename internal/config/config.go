// Package config handles loading and validating application configuration
// from environment variables.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	EmbyAPIURL       string       // EMBY_API_URL
	EmbyAPIKey       string       // EMBY_API_KEY
	TemplateUserName string       // TEMPLATE_USER_NAME
	TrustedProxies   []*net.IPNet // TRUSTED_PROXIES (parsed CIDR/IPs)
	BridgePort       int          // BRIDGE_PORT (default: 8080)
	DatabasePath     string       // DATABASE_PATH (default: /data/users.db)
	OIDCIssuerURL    string       // OIDC_ISSUER_URL (optional, for profile image sync)
	WatchpartyURL    string       // EMBY_WATCHPARTY_URL (optional, enables watchparty feature)
}

// WatchpartyEnabled returns true if the watchparty feature is enabled.
func (c *Config) WatchpartyEnabled() bool {
	return c.WatchpartyURL != ""
}

// Load reads configuration from environment variables.
// Returns an error naming the specific missing variable if a required var is absent.
func Load() (*Config, error) {
	embyAPIURL, err := requireEnv("EMBY_API_URL")
	if err != nil {
		return nil, err
	}

	embyAPIKey, err := requireEnv("EMBY_API_KEY")
	if err != nil {
		return nil, err
	}

	templateUserName, err := requireEnv("TEMPLATE_USER_NAME")
	if err != nil {
		return nil, err
	}

	trustedProxiesRaw, err := requireEnv("TRUSTED_PROXIES")
	if err != nil {
		return nil, err
	}

	trustedProxies, err := ParseTrustedProxies(trustedProxiesRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing TRUSTED_PROXIES: %w", err)
	}

	bridgePort := 8080
	if portStr := os.Getenv("BRIDGE_PORT"); portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("parsing BRIDGE_PORT: %w", err)
		}
		bridgePort = p
	}

	databasePath := "/data/users.db"
	if dbPath := os.Getenv("DATABASE_PATH"); dbPath != "" {
		databasePath = dbPath
	}

	oidcIssuerURL := os.Getenv("OIDC_ISSUER_URL")

	watchpartyURL := strings.TrimSpace(os.Getenv("EMBY_WATCHPARTY_URL"))
	if watchpartyURL != "" {
		u, err := url.Parse(watchpartyURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("EMBY_WATCHPARTY_URL: invalid URL: %s", watchpartyURL)
		}
	}

	return &Config{
		EmbyAPIURL:       embyAPIURL,
		EmbyAPIKey:       embyAPIKey,
		TemplateUserName: templateUserName,
		TrustedProxies:   trustedProxies,
		BridgePort:       bridgePort,
		DatabasePath:     databasePath,
		OIDCIssuerURL:    oidcIssuerURL,
		WatchpartyURL:    watchpartyURL,
	}, nil
}

// ParseTrustedProxies parses a comma-separated list of IPs/CIDRs into []*net.IPNet.
// Plain IP addresses are converted to /32 (IPv4) or /128 (IPv6) networks.
func ParseTrustedProxies(raw string) ([]*net.IPNet, error) {
	var networks []*net.IPNet

	entries := strings.Split(raw, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Try parsing as CIDR first
		_, network, err := net.ParseCIDR(entry)
		if err == nil {
			networks = append(networks, network)
			continue
		}

		// Try parsing as a plain IP address
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %q", entry)
		}

		// Convert plain IP to a /32 or /128 network
		if ip4 := ip.To4(); ip4 != nil {
			networks = append(networks, &net.IPNet{
				IP:   ip4,
				Mask: net.CIDRMask(32, 32),
			})
		} else {
			networks = append(networks, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(128, 128),
			})
		}
	}

	if len(networks) == 0 {
		return nil, fmt.Errorf("no valid entries in TRUSTED_PROXIES")
	}

	return networks, nil
}

// requireEnv reads an environment variable and returns an error if it is not set or empty.
func requireEnv(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}
