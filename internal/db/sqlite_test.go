package db_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/xyxxyxxy/emby-web-oidc-bridge/internal/db"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
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

	err = database.InsertUser("sub-123", "user123", "abcd1234")
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

	err = database.InsertUser("sub-dup", "user123", "abcd1234")
	if err != nil {
		t.Fatalf("first InsertUser failed: %v", err)
	}

	err = database.InsertUser("sub-dup", "user456", "efgh5678")
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

	err = database.InsertUser("sub-del", "user-del-1", "pass1234")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	record, err := database.FindUserBySub("sub-del")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record == nil {
		t.Fatal("expected user to exist before deletion")
	}

	err = database.DeleteUser("sub-del")
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

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

	err = database.InsertUser("sub-pic", "user-pic-1", "picpass")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

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

	err = database.UpdatePictureURL("sub-pic", "https://example.com/avatar.png")
	if err != nil {
		t.Fatalf("UpdatePictureURL failed: %v", err)
	}

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

	err = database.InsertUser("sub-pic2", "user-pic-2", "picpass2")
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}

	err = database.UpdatePictureURL("sub-pic2", "https://example.com/old.png")
	if err != nil {
		t.Fatalf("first UpdatePictureURL failed: %v", err)
	}

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

func TestMigrateSchema_v1ToV2(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate.db")
	uri := "file:" + dbPath + "?mode=rwc"

	conn, err := sqlite.OpenConn(dbPath, sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}

	legacySchema := `CREATE TABLE users (
  oidc_sub TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL DEFAULT '',
  emby_user_id TEXT NOT NULL,
  password TEXT NOT NULL,
  picture_url TEXT NOT NULL DEFAULT '',
  picture_synced_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`
	if err := sqlitex.ExecuteScript(conn, legacySchema, nil); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	err = sqlitex.Execute(conn, `INSERT INTO users (oidc_sub, name, email, emby_user_id, password, picture_url)
VALUES ('sub-migrate', 'Legacy Name', 'legacy@example.com', 'emby-legacy-1', 'legacypass', 'https://example.com/pic.png')`, nil)
	if err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close legacy conn: %v", err)
	}

	database, err := db.Open(uri)
	if err != nil {
		t.Fatalf("Open migration failed: %v", err)
	}
	defer func() { _ = database.Close() }()

	conn, err = sqlite.OpenConn(dbPath, sqlite.OpenReadWrite)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var userVersion int
	err = sqlitex.Execute(conn, "PRAGMA user_version", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			userVersion = int(stmt.ColumnInt64(0))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if userVersion != 2 {
		t.Errorf("user_version = %d, want 2", userVersion)
	}

	hasNameColumn := false
	err = sqlitex.Execute(conn, "PRAGMA table_info(users)", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			if stmt.GetText("name") == "name" {
				hasNameColumn = true
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	if hasNameColumn {
		t.Error("expected name column to be removed after migration")
	}

	record, err := database.FindUserBySub("sub-migrate")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record == nil {
		t.Fatal("expected migrated user record")
	}
	if record.EmbyUserID != "emby-legacy-1" {
		t.Errorf("EmbyUserID = %q, want emby-legacy-1", record.EmbyUserID)
	}
	if record.Password != "legacypass" {
		t.Errorf("Password = %q, want legacypass", record.Password)
	}
	if record.PictureURL != "https://example.com/pic.png" {
		t.Errorf("PictureURL = %q, want https://example.com/pic.png", record.PictureURL)
	}

	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("cleanup db file: %v", err)
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
