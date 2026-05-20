package db_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
)

var propertyDBCounter atomic.Int64

// propertyDBURI returns a unique in-memory database URI for each property test run.
func propertyDBURI() string {
	n := propertyDBCounter.Add(1)
	return fmt.Sprintf("file:propdb%d?mode=memory&cache=shared", n)
}

// Feature: emby-auth-bridge, Property 3: Database user record round-trip
// **Validates: Requirements 3.4, 9.3**
func TestDatabaseRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		database, err := db.Open(propertyDBURI())
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		defer database.Close()

		sub := rapid.StringMatching(`[a-z0-9]{8,20}`).Draw(t, "sub")
		name := rapid.StringMatching(`[A-Za-z ]{3,20}`).Draw(t, "name")
		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		userID := rapid.StringMatching(`[a-f0-9]{32}`).Draw(t, "userID")
		password := rapid.StringMatching(`[a-z0-9]{8}`).Draw(t, "password")

		err = database.InsertUser(sub, name, email, userID, password)
		if err != nil {
			t.Fatalf("InsertUser failed: %v", err)
		}

		record, err := database.FindUserBySub(sub)
		if err != nil {
			t.Fatalf("FindUserBySub failed: %v", err)
		}

		if record == nil {
			t.Fatalf("FindUserBySub returned nil for sub %q after insert", sub)
		}

		if record.OIDCSub != sub {
			t.Fatalf("OIDCSub mismatch: got %q, want %q", record.OIDCSub, sub)
		}
		if record.Name != name {
			t.Fatalf("Name mismatch: got %q, want %q", record.Name, name)
		}
		if record.Email != email {
			t.Fatalf("Email mismatch: got %q, want %q", record.Email, email)
		}
		if record.EmbyUserID != userID {
			t.Fatalf("EmbyUserID mismatch: got %q, want %q", record.EmbyUserID, userID)
		}
		if record.Password != password {
			t.Fatalf("Password mismatch: got %q, want %q", record.Password, password)
		}
	})
}

// Feature: emby-auth-bridge, Property 4: Password stability
// **Validates: Requirements 3.6**
func TestPasswordStability(t *testing.T) {
	database, err := db.Open(propertyDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	rapid.Check(t, func(t *rapid.T) {
		sub := rapid.StringMatching(`[a-z0-9]{8,20}`).Draw(t, "sub")
		name := rapid.StringMatching(`[A-Za-z ]{3,20}`).Draw(t, "name")
		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		userID := rapid.StringMatching(`[a-f0-9]{32}`).Draw(t, "userID")
		password := rapid.StringMatching(`[a-z0-9]{8}`).Draw(t, "password")

		err := database.InsertUser(sub, name, email, userID, password)
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}

		// Query the user multiple times and verify the password never changes
		lookups := rapid.IntRange(2, 10).Draw(t, "lookups")
		for i := 0; i < lookups; i++ {
			record, err := database.FindUserBySub(sub)
			if err != nil {
				t.Fatalf("FindUserBySub (lookup %d) failed: %v", i+1, err)
			}
			if record == nil {
				t.Fatalf("FindUserBySub (lookup %d) returned nil for existing user %q", i+1, sub)
			}
			if record.Password != password {
				t.Fatalf("password changed on lookup %d: got %q, want %q", i+1, record.Password, password)
			}
		}
	})
}
