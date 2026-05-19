package middleware_test

import (
	"fmt"
	"net"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/middleware"
)

// Feature: emby-auth-bridge, Property 2: Trusted proxy IP matching
// **Validates: Requirements 1.2**
func TestTrustedProxyIPMatching(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random CIDR network
		prefix := rapid.IntRange(8, 28).Draw(t, "prefix")
		baseIP := net.IPv4(
			byte(rapid.IntRange(1, 254).Draw(t, "oct1")),
			byte(rapid.IntRange(0, 254).Draw(t, "oct2")),
			byte(rapid.IntRange(0, 254).Draw(t, "oct3")),
			byte(rapid.IntRange(0, 254).Draw(t, "oct4")),
		)
		_, network, _ := net.ParseCIDR(baseIP.String() + "/" + fmt.Sprint(prefix))
		trusted := []*net.IPNet{network}

		// Generate a random IP to test against
		testIP := net.IPv4(
			byte(rapid.IntRange(1, 254).Draw(t, "tip1")),
			byte(rapid.IntRange(0, 254).Draw(t, "tip2")),
			byte(rapid.IntRange(0, 254).Draw(t, "tip3")),
			byte(rapid.IntRange(0, 254).Draw(t, "tip4")),
		)

		result := middleware.IsIPTrusted(testIP, trusted)
		expected := network.Contains(testIP)

		if result != expected {
			t.Fatalf("IsIPTrusted(%v, %v) = %v, want %v", testIP, network, result, expected)
		}
	})
}
