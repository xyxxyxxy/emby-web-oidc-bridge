package db

import (
	"context"
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const schema = `CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  emby_user_id TEXT NOT NULL,
  password TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`

// UserRecord represents a row in the users table.
type UserRecord struct {
	Email      string
	EmbyUserID string
	Password   string
	CreatedAt  time.Time
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
		pool.Close()
		return nil, fmt.Errorf("open database: take connection: %w", err)
	}
	defer pool.Put(conn)

	err = sqlitex.ExecuteScript(conn, schema, nil)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("open database: initialize schema: %w", err)
	}

	return &DB{pool: pool}, nil
}

// FindUser queries a user by email. Returns nil if not found.
func (d *DB) FindUser(email string) (*UserRecord, error) {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return nil, fmt.Errorf("find user: take connection: %w", err)
	}
	defer d.pool.Put(conn)

	var record *UserRecord
	err = sqlitex.Execute(conn, "SELECT email, emby_user_id, password, created_at FROM users WHERE email = :email", &sqlitex.ExecOptions{
		Named: map[string]any{
			":email": email,
		},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			createdAtStr := stmt.GetText("created_at")
			createdAt, parseErr := time.Parse("2006-01-02 15:04:05", createdAtStr)
			if parseErr != nil {
				createdAt = time.Time{}
			}
			record = &UserRecord{
				Email:      stmt.GetText("email"),
				EmbyUserID: stmt.GetText("emby_user_id"),
				Password:   stmt.GetText("password"),
				CreatedAt:  createdAt,
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}

	return record, nil
}

// InsertUser inserts a new user record into the database.
func (d *DB) InsertUser(email, embyUserID, password string) error {
	conn, err := d.pool.Take(context.Background())
	if err != nil {
		return fmt.Errorf("insert user: take connection: %w", err)
	}
	defer d.pool.Put(conn)

	err = sqlitex.Execute(conn, "INSERT INTO users (email, emby_user_id, password) VALUES (:email, :emby_user_id, :password)", &sqlitex.ExecOptions{
		Named: map[string]any{
			":email":        email,
			":emby_user_id": embyUserID,
			":password":     password,
		},
	})
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
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
