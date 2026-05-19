package db_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
)

var testDBCounter atomic.Int64

// testDBURI returns a unique in-memory database URI for each test to avoid shared state.
func testDBURI() string {
	n := testDBCounter.Add(1)
	return fmt.Sprintf("file:testdb%d?mode=memory&cache=shared", n)
}

func TestOpen(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()
}

func TestInsertAndFindUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	err = database.InsertUser("alice@example.com", "user123", "abcd1234")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	record, err := database.FindUser("alice@example.com")
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if record == nil {
		t.Fatal("FindUser returned nil for existing user")
	}
	if record.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", record.Email, "alice@example.com")
	}
	if record.EmbyUserID != "user123" {
		t.Errorf("EmbyUserID = %q, want %q", record.EmbyUserID, "user123")
	}
	if record.Password != "abcd1234" {
		t.Errorf("Password = %q, want %q", record.Password, "abcd1234")
	}
	if record.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, expected a valid timestamp")
	}
}

func TestFindUserNotFound(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	record, err := database.FindUser("nonexistent@example.com")
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if record != nil {
		t.Errorf("FindUser returned %+v, want nil for non-existent user", record)
	}
}

func TestInsertDuplicateUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	err = database.InsertUser("alice@example.com", "user123", "abcd1234")
	if err != nil {
		t.Fatalf("first InsertUser failed: %v", err)
	}

	err = database.InsertUser("alice@example.com", "user456", "efgh5678")
	if err == nil {
		t.Fatal("second InsertUser should have failed for duplicate email")
	}
}

func TestIsHealthy(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !database.IsHealthy() {
		t.Error("IsHealthy() = false, want true for open database")
	}

	database.Close()

	if database.IsHealthy() {
		t.Error("IsHealthy() = true, want false for closed database")
	}
}

func TestClose(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	err = database.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
