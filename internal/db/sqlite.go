package db

import (
	"context"
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const schemaVersion = 2

const schemaV2 = `CREATE TABLE IF NOT EXISTS users (
  oidc_sub TEXT PRIMARY KEY,
  emby_user_id TEXT NOT NULL,
  password TEXT NOT NULL,
  picture_url TEXT NOT NULL DEFAULT '',
  picture_synced_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`

// UserRecord represents a row in the users table.
type UserRecord struct {
	OIDCSub         string
	EmbyUserID      string
	Password        string
	PictureURL      string
	PictureSyncedAt time.Time
	CreatedAt       time.Time
}

// DB wraps SQLite database operations.
type DB struct {
	pool *sqlitex.Pool
}

// Open opens (or creates) the SQLite database at the given path and initializes the schema.
// For in-memory databases (testing), use "file::memory:?mode=memory&cache=shared".
func Open(path string) (*DB, error) {
	flags := sqlite.OpenReadWrite | sqlite.OpenCreate | sqlite.OpenURI | sqlite.OpenWAL
	pool, err := sqlitex.NewPool(path, sqlitex.PoolOptions{
		Flags:    flags,
		PoolSize: 10,
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn, err := pool.Take(context.Background())
	if err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("open database: take connection: %w", err)
	}

	if err := sqlitex.ExecuteScript(conn, schemaV2, nil); err != nil {
		pool.Put(conn)
		_ = pool.Close()
		return nil, fmt.Errorf("open database: initialize schema: %w", err)
	}

	if err := migrateSchema(conn); err != nil {
		pool.Put(conn)
		_ = pool.Close()
		return nil, fmt.Errorf("open database: migrate schema: %w", err)
	}

	pool.Put(conn)
	return &DB{pool: pool}, nil
}

func migrateSchema(conn *sqlite.Conn) error {
	var version int
	err := sqlitex.Execute(conn, "PRAGMA user_version", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			version = int(stmt.ColumnInt64(0))
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if version >= schemaVersion {
		return nil
	}

	if version < schemaVersion && usersTableHasColumn(conn, "name") {
		if err := migrateV1ToV2(conn); err != nil {
			return err
		}
	}

	return sqlitex.Execute(conn, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion), nil)
}

func usersTableHasColumn(conn *sqlite.Conn, column string) bool {
	found := false
	_ = sqlitex.Execute(conn, "PRAGMA table_info(users)", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			if stmt.GetText("name") == column {
				found = true
			}
			return nil
		},
	})
	return found
}

func migrateV1ToV2(conn *sqlite.Conn) (err error) {
	end := sqlitex.Transaction(conn)
	defer end(&err)

	err = sqlitex.ExecuteScript(conn, `CREATE TABLE users_v2 (
  oidc_sub TEXT PRIMARY KEY,
  emby_user_id TEXT NOT NULL,
  password TEXT NOT NULL,
  picture_url TEXT NOT NULL DEFAULT '',
  picture_synced_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`, nil)
	if err != nil {
		return fmt.Errorf("create users_v2: %w", err)
	}

	err = sqlitex.Execute(conn, `INSERT INTO users_v2 (oidc_sub, emby_user_id, password, picture_url, picture_synced_at, created_at)
SELECT oidc_sub, emby_user_id, password, picture_url, picture_synced_at, created_at FROM users`, nil)
	if err != nil {
		return fmt.Errorf("copy users to users_v2: %w", err)
	}

	err = sqlitex.Execute(conn, "DROP TABLE users", nil)
	if err != nil {
		return fmt.Errorf("drop legacy users table: %w", err)
	}

	err = sqlitex.Execute(conn, "ALTER TABLE users_v2 RENAME TO users", nil)
	if err != nil {
		return fmt.Errorf("rename users_v2: %w", err)
	}

	return nil
}

// FindUserBySub queries a user by OIDC subject identifier. Returns nil if not found.
func (d *DB) FindUserBySub(sub string) (*UserRecord, error) {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return nil, fmt.Errorf("find user by sub: take connection: %w", err)
	}
	defer d.pool.Put(conn)

	var record *UserRecord
	err = sqlitex.Execute(conn, "SELECT oidc_sub, emby_user_id, password, picture_url, picture_synced_at, created_at FROM users WHERE oidc_sub = :sub", &sqlitex.ExecOptions{
		Named: map[string]any{
			":sub": sub,
		},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			record = scanUserRecord(stmt)
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("find user by sub: %w", err)
	}

	return record, nil
}

// InsertUser inserts a new user record into the database.
func (d *DB) InsertUser(sub, embyUserID, password string) error {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("insert user: take connection: %w", err)
	}
	defer d.pool.Put(conn)

	err = sqlitex.Execute(conn, "INSERT INTO users (oidc_sub, emby_user_id, password) VALUES (:sub, :emby_user_id, :password)", &sqlitex.ExecOptions{
		Named: map[string]any{
			":sub":          sub,
			":emby_user_id": embyUserID,
			":password":     password,
		},
	})
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	return nil
}

// DeleteUser removes a user record from the database by OIDC subject.
func (d *DB) DeleteUser(sub string) error {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("delete user: take connection: %w", err)
	}
	defer d.pool.Put(conn)

	err = sqlitex.Execute(conn, "DELETE FROM users WHERE oidc_sub = :sub", &sqlitex.ExecOptions{
		Named: map[string]any{
			":sub": sub,
		},
	})
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}

	return nil
}

// UpdatePictureURL updates the stored picture URL for a user.
func (d *DB) UpdatePictureURL(sub, pictureURL string) error {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("update picture url: take connection: %w", err)
	}
	defer d.pool.Put(conn)

	err = sqlitex.Execute(conn, "UPDATE users SET picture_url = :picture_url, picture_synced_at = datetime('now') WHERE oidc_sub = :sub", &sqlitex.ExecOptions{
		Named: map[string]any{
			":sub":         sub,
			":picture_url": pictureURL,
		},
	})
	if err != nil {
		return fmt.Errorf("update picture url: %w", err)
	}

	return nil
}

// IsHealthy verifies database connectivity by executing a simple query.
func (d *DB) IsHealthy() bool {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return false
	}
	defer d.pool.Put(conn)

	err = sqlitex.Execute(conn, "SELECT 1", &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			return nil
		},
	})
	return err == nil
}

// Close closes the database pool and releases all resources.
func (d *DB) Close() error {
	return d.pool.Close()
}

// scanUserRecord extracts a UserRecord from a SQLite statement row.
func scanUserRecord(stmt *sqlite.Stmt) *UserRecord {
	pictureSyncedAtStr := stmt.GetText("picture_synced_at")
	pictureSyncedAt, parseErr := time.Parse("2006-01-02 15:04:05", pictureSyncedAtStr)
	if parseErr != nil {
		pictureSyncedAt = time.Time{}
	}
	createdAtStr := stmt.GetText("created_at")
	createdAt, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr)
	if parseErr != nil {
		createdAt = time.Time{}
	}
	return &UserRecord{
		OIDCSub:         stmt.GetText("oidc_sub"),
		EmbyUserID:      stmt.GetText("emby_user_id"),
		Password:        stmt.GetText("password"),
		PictureURL:      stmt.GetText("picture_url"),
		PictureSyncedAt: pictureSyncedAt,
		CreatedAt:       createdAt,
	}
}
