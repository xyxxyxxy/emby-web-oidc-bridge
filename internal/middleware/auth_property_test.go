package middleware

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: emby-watchparty-support, Property 5: Username resolution ordering
// **Validates: Requirements 3.2**
func TestUsernameResolutionOrdering(t *testing.T) {
	// nonEmptyString generates a non-empty string for use as a username field.
	nonEmptyString := rapid.StringMatching(`[a-zA-Z0-9._@+\-]{1,50}`)

	// optionalString generates either an empty string or a non-empty string.
	optionalString := rapid.OneOf(
		rapid.Just(""),
		nonEmptyString,
	)

	rapid.Check(t, func(t *rapid.T) {
		// Generate random (preferred_username, name, email) triples.
		preferredUsername := optionalString.Draw(t, "preferredUsername")
		name := optionalString.Draw(t, "name")
		email := optionalString.Draw(t, "email")

		// At least one must be non-empty — filter out all-empty triples.
		if preferredUsername == "" && name == "" && email == "" {
			return
		}

		headers := OIDCHeaders{
			PreferredUsername: preferredUsername,
			Name:              name,
			Email:             email,
		}

		got := headers.embyUsername()

		// Compute expected: first non-empty in order preferred_username > name > email.
		var expected string
		switch {
		case preferredUsername != "":
			expected = preferredUsername
		case name != "":
			expected = name
		default:
			expected = email
		}

		if got != expected {
			t.Fatalf("embyUsername() = %q, expected %q (preferred_username=%q, name=%q, email=%q)",
				got, expected, preferredUsername, name, email)
		}
	})
}
