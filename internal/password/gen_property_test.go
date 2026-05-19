package password_test

import (
	"regexp"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/password"
)

// Feature: emby-auth-bridge, Property 1: Password format invariant
// **Validates: Requirements 3.1**
func TestPasswordFormatInvariant(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9]{8}$`)
	rapid.Check(t, func(t *rapid.T) {
		pw := password.Generate()
		if !re.MatchString(pw) {
			t.Fatalf("password %q does not match format ^[a-z0-9]{8}$", pw)
		}
	})
}
