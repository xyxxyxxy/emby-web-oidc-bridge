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
	if userVersion != 3 {
		t.Errorf("user_version = %d, want 3", userVersion)
	}

	hasNameColumn := false
	hasPictureURLColumn := false
	err = sqlitex.Execute(conn, "PRAGMA table_info(users)", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			col := stmt.GetText("name")
			if col == "name" {
				hasNameColumn = true
			}
			if col == "picture_url" {
				hasPictureURLColumn = true
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
	if hasPictureURLColumn {
		t.Error("expected picture_url column to be removed after migration")
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

	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("cleanup db file: %v", err)
	}
}

func TestMigrateSchema_v2ToV3(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate-v2.db")
	uri := "file:" + dbPath + "?mode=rwc"

	conn, err := sqlite.OpenConn(dbPath, sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatalf("open v2 db: %v", err)
	}

	v2Schema := `CREATE TABLE users (
  oidc_sub TEXT PRIMARY KEY,
  emby_user_id TEXT NOT NULL,
  password TEXT NOT NULL,
  picture_url TEXT NOT NULL DEFAULT '',
  picture_synced_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`
	if err := sqlitex.ExecuteScript(conn, v2Schema, nil); err != nil {
		t.Fatalf("create v2 schema: %v", err)
	}
	err = sqlitex.Execute(conn, `INSERT INTO users (oidc_sub, emby_user_id, password, picture_url, picture_synced_at)
VALUES ('sub-v2', 'emby-v2-1', 'v2pass', 'https://example.com/old.png', datetime('now'))`, nil)
	if err != nil {
		t.Fatalf("insert v2 row: %v", err)
	}
	if err := sqlitex.Execute(conn, "PRAGMA user_version = 2", nil); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close v2 conn: %v", err)
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
	if userVersion != 3 {
		t.Errorf("user_version = %d, want 3", userVersion)
	}

	hasPictureURLColumn := false
	err = sqlitex.Execute(conn, "PRAGMA table_info(users)", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			if stmt.GetText("name") == "picture_url" {
				hasPictureURLColumn = true
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	if hasPictureURLColumn {
		t.Error("expected picture_url column to be removed after v2→v3 migration")
	}

	record, err := database.FindUserBySub("sub-v2")
	if err != nil {
		t.Fatalf("FindUserBySub failed: %v", err)
	}
	if record == nil {
		t.Fatal("expected migrated user record")
	}
	if record.EmbyUserID != "emby-v2-1" {
		t.Errorf("EmbyUserID = %q, want emby-v2-1", record.EmbyUserID)
	}
	if record.Password != "v2pass" {
		t.Errorf("Password = %q, want v2pass", record.Password)
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
