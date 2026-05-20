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

func TestDeleteUser(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	// Insert a user first.
	err = database.InsertUser("delete@example.com", "user-del-1", "pass1234")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Verify user exists.
	record, err := database.FindUser("delete@example.com")
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if record == nil {
		t.Fatal("expected user to exist before deletion")
	}

	// Delete the user.
	err = database.DeleteUser("delete@example.com")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Verify user is gone.
	record, err = database.FindUser("delete@example.com")
	if err != nil {
		t.Fatalf("FindUser after delete failed: %v", err)
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
	defer database.Close()

	// Deleting a non-existent user should not error (DELETE WHERE is a no-op).
	err = database.DeleteUser("ghost@example.com")
	if err != nil {
		t.Fatalf("DeleteUser for non-existent user failed: %v", err)
	}
}

func TestUpdatePictureURL(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	// Insert a user.
	err = database.InsertUser("pic@example.com", "user-pic-1", "picpass")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Verify initial state: no picture URL.
	record, err := database.FindUser("pic@example.com")
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if record.PictureURL != "" {
		t.Errorf("expected empty PictureURL initially, got %q", record.PictureURL)
	}
	if !record.PictureSyncedAt.IsZero() {
		t.Errorf("expected zero PictureSyncedAt initially, got %v", record.PictureSyncedAt)
	}

	// Update picture URL.
	err = database.UpdatePictureURL("pic@example.com", "https://example.com/avatar.png")
	if err != nil {
		t.Fatalf("UpdatePictureURL failed: %v", err)
	}

	// Verify updated state.
	record, err = database.FindUser("pic@example.com")
	if err != nil {
		t.Fatalf("FindUser after update failed: %v", err)
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
	defer database.Close()

	err = database.InsertUser("pic2@example.com", "user-pic-2", "picpass2")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	// Set first picture.
	err = database.UpdatePictureURL("pic2@example.com", "https://example.com/old.png")
	if err != nil {
		t.Fatalf("first UpdatePictureURL failed: %v", err)
	}

	// Overwrite with new picture.
	err = database.UpdatePictureURL("pic2@example.com", "https://example.com/new.png")
	if err != nil {
		t.Fatalf("second UpdatePictureURL failed: %v", err)
	}

	record, err := database.FindUser("pic2@example.com")
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if record.PictureURL != "https://example.com/new.png" {
		t.Errorf("PictureURL = %q, want %q", record.PictureURL, "https://example.com/new.png")
	}
}

func TestMigrations_ColumnsExist(t *testing.T) {
	database, err := db.Open(testDBURI())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	// Insert a user and verify picture columns are accessible.
	err = database.InsertUser("migrate@example.com", "user-mig", "migpass")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	record, err := database.FindUser("migrate@example.com")
	if err != nil {
		t.Fatalf("FindUser failed: %v", err)
	}
	if record == nil {
		t.Fatal("expected user record, got nil")
	}
	// picture_url and picture_synced_at should have default empty values.
	if record.PictureURL != "" {
		t.Errorf("expected empty PictureURL default, got %q", record.PictureURL)
	}
	if !record.PictureSyncedAt.IsZero() {
		t.Errorf("expected zero PictureSyncedAt default, got %v", record.PictureSyncedAt)
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
