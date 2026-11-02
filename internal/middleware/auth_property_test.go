package middleware

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: emby-auth-bridge, Property 5: Username resolution uses preferred_username only
func TestUsernameResolutionOrdering(t *testing.T) {
	nonEmptyString := rapid.StringMatching(`[a-zA-Z0-9._@+\-]{1,50}`)
	optionalString := rapid.OneOf(
		rapid.Just(""),
		nonEmptyString,
	)

	rapid.Check(t, func(t *rapid.T) {
		preferredUsername := optionalString.Draw(t, "preferredUsername")
		email := optionalString.Draw(t, "email")

		headers := OIDCHeaders{
			PreferredUsername: preferredUsername,
			Email:             email,
		}

		got := headers.embyUsername()
		if got != preferredUsername {
			t.Fatalf("embyUsername() = %q, expected %q (preferred_username=%q, email=%q)",
				got, preferredUsername, preferredUsername, email)
		}
	})
}
