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
	defer func() { _ = database.Close() }()
}

func TestInsertAndFindUserBySub(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-123", "Alice", "alice@example.com", "user123", "abcd1234")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	record, err := database.FindUserBySub("sub-123")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record == nil {
		t.Fatal("FindUserBySub returned nil for existing user")
	}
	if record.OIDCSub != "sub-123" {
		t.Errorf("OIDCSub = %q, want %q", record.OIDCSub, "sub-123")
	}
	if record.Name != "Alice" {
		t.Errorf("Name = %q, want %q", record.Name, "Alice")
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

func TestFindUserBySubNotFound(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	record, err := database.FindUserBySub("nonexistent-sub")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record != nil {
		t.Errorf("FindUserBySub returned %+v, want nil for non-existent user", record)
	}
}

func TestInsertDuplicateUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-dup", "Alice", "alice@example.com", "user123", "abcd1234")
	if err != nil {
		t.Fatalf("first InsertUser failed: %v", err)
	}

	err = database.InsertUser("sub-dup", "Bob", "bob@example.com", "user456", "efgh5678")
	if err == nil {
		t.Fatal("second InsertUser should have failed for duplicate sub")
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

	_ = database.Close()

	if database.IsHealthy() {
		t.Error("IsHealthy() = true, want false for closed database")
	}
}

func TestDeleteUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	// Insert a user first.
	err = database.InsertUser("sub-del", "Delete Me", "delete@example.com", "user-del-1", "pass1234")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Verify user exists.
	record, err := database.FindUserBySub("sub-del")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record == nil {
		t.Fatal("expected user to exist before deletion")
	}

	// Delete the user.
	err = database.DeleteUser("sub-del")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user is gone.
	record, err = database.FindUserBySub("sub-del")
	if err != nil {
		t.Fatalf("FindUserBySub after delete failed: %v", err)
	}
	if record != nil {
		t.Errorf("expected nil after deletion, got %+v", record)
	}
}

func TestDeleteUser_NonExistent(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	// Deleting a non-existent user should not error (DELETE WHERE is a no-op).
	err = database.DeleteUser("ghost-sub")
	if err != nil {
		t.Fatalf("DeleteUser for non-existent user failed: %v", err)
	}
}

func TestUpdatePictureURL(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	// Insert a user.
	err = database.InsertUser("sub-pic", "Pic User", "pic@example.com", "user-pic-1", "picpass")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Verify initial state: no picture URL.
	record, err := database.FindUserBySub("sub-pic")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record.PictureURL != "" {
		t.Errorf("expected empty PictureURL initially, got %q", record.PictureURL)
	}
	if !record.PictureSyncedAt.IsZero() {
		t.Errorf("expected zero PictureSyncedAt initially, got %v", record.PictureSyncedAt)
	}

	// Update picture URL.
	err = database.UpdatePictureURL("sub-pic", "https://example.com/avatar.png")
	if err != nil {
		t.Fatalf("UpdatePictureURL failed: %v", err)
	}

	// Verify updated state.
	record, err = database.FindUserBySub("sub-pic")
	if err != nil {
		t.Fatalf("FindUserBySub after update failed: %v", err)
	}
	if record.PictureURL != "https://example.com/avatar.png" {
		t.Errorf("PictureURL = %q, want %q", record.PictureURL, "https://example.com/avatar.png")
	}
	if record.PictureSyncedAt.IsZero() {
		t.Error("PictureSyncedAt should be set after UpdatePictureURL")
	}
}

func TestUpdatePictureURL_OverwritesPrevious(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-pic2", "Pic2", "pic2@example.com", "user-pic-2", "picpass2")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Set first picture.
	err = database.UpdatePictureURL("sub-pic2", "https://example.com/old.png")
	if err != nil {
		t.Fatalf("first UpdatePictureURL failed: %v", err)
	}

	// Overwrite with new picture.
	err = database.UpdatePictureURL("sub-pic2", "https://example.com/new.png")
	if err != nil {
		t.Fatalf("second UpdatePictureURL failed: %v", err)
	}

	record, err := database.FindUserBySub("sub-pic2")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record.PictureURL != "https://example.com/new.png" {
		t.Errorf("PictureURL = %q, want %q", record.PictureURL, "https://example.com/new.png")
	}
}

func TestUpdateUserIdentity(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	err = database.InsertUser("sub-identity", "Old Name", "old@example.com", "user-id-1", "pass123")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Update identity.
	err = database.UpdateUserIdentity("sub-identity", "New Name", "new@example.com")
	if err != nil {
		t.Fatalf("UpdateUserIdentity failed: %v", err)
	}

	record, err := database.FindUserBySub("sub-identity")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record.Name != "New Name" {
		t.Errorf("Name = %q, want %q", record.Name, "New Name")
	}
	if record.Email != "new@example.com" {
		t.Errorf("Email = %q, want %q", record.Email, "new@example.com")
	}
	// Other fields should be unchanged.
	if record.EmbyUserID != "user-id-1" {
		t.Errorf("EmbyUserID = %q, want %q", record.EmbyUserID, "user-id-1")
	}
	if record.Password != "pass123" {
		t.Errorf("Password = %q, want %q", record.Password, "pass123")
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
