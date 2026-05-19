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

		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		userID := rapid.StringMatching(`[a-f0-9]{32}`).Draw(t, "userID")
		password := rapid.StringMatching(`[a-z0-9]{8}`).Draw(t, "password")

		err = database.InsertUser(email, userID, password)
		if err != nil {
			t.Fatalf("InsertUser failed: %v", err)
		}

		record, err := database.FindUser(email)
		if err != nil {
			t.Fatalf("FindUser failed: %v", err)
		}

		if record == nil {
			t.Fatalf("FindUser returned nil for email %q after insert", email)
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
		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		userID := rapid.StringMatching(`[a-f0-9]{32}`).Draw(t, "userID")
		password := rapid.StringMatching(`[a-z0-9]{8}`).Draw(t, "password")

		err := database.InsertUser(email, userID, password)
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}

		// Query the user multiple times and verify the password never changes
		lookups := rapid.IntRange(2, 10).Draw(t, "lookups")
		for i := 0; i < lookups; i++ {
			record, err := database.FindUser(email)
			if err != nil {
				t.Fatalf("FindUser (lookup %d) failed: %v", i+1, err)
			}
			if record == nil {
				t.Fatalf("FindUser (lookup %d) returned nil for existing user %q", i+1, email)
			}
			if record.Password != password {
				t.Fatalf("password changed on lookup %d: got %q, want %q", i+1, record.Password, password)
			}
		}
	})
}
