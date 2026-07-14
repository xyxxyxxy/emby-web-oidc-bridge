package middleware

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: emby-watchparty-support, Property 5: Username resolution uses preferred_username only
// **Validates: Requirements 3.2**
func TestUsernameResolutionOrdering(t *testing.T) {
	nonEmptyString := rapid.StringMatching(`[a-zA-Z0-9._@+\-]{1,50}`)
	optionalString := rapid.OneOf(
		rapid.Just(""),
		nonEmptyString,
	)

	rapid.Check(t, func(t *rapid.T) {
		preferredUsername := optionalString.Draw(t, "preferredUsername")
		name := optionalString.Draw(t, "name")
		email := optionalString.Draw(t, "email")

		headers := OIDCHeaders{
			PreferredUsername: preferredUsername,
			Name:              name,
			Email:             email,
		}

		got := headers.embyUsername()
		if got != preferredUsername {
			t.Fatalf("embyUsername() = %q, expected %q (preferred_username=%q, name=%q, email=%q)",
				got, preferredUsername, preferredUsername, name, email)
		}
	})
}
