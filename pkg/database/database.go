// Package database provides embedded SQLite storage for user management and authentication.
// Uses modernc.org/sqlite — pure Go, no CGO required — maintaining the "Zero Install" single-binary requirement.

package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	bootstrapAdminUsernameEnv = "TRACESLEUTH_BOOTSTRAP_ADMIN_USERNAME"
	bootstrapAdminPasswordEnv = "TRACESLEUTH_BOOTSTRAP_ADMIN_PASSWORD"
	minimumPasswordLength     = 12
)

// UserRole defines the role-based access control levels.
type UserRole string

const (
	RoleAdmin   UserRole = "admin"
	RoleAnalyst UserRole = "analyst"
	RoleViewer  UserRole = "viewer"
)

// User represents a user record in the database.
type User struct {
	ID           int64    `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"-"`
	Role         UserRole `json:"role"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	LastLogin    *string  `json:"last_login,omitempty"`
	IsActive     bool     `json:"is_active"`
}

// DB wraps the SQLite connection with user management methods.
type DB struct {
	conn *sql.DB
	mu   sync.RWMutex
}

// Open initializes the SQLite database at the given path, creates tables, and
// securely bootstraps the first administrator only when explicit environment
// variables are supplied. TraceSleuth never creates a universal default
// credential.
func Open(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// SQLite performance pragmas.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", p, err)
		}
	}

	db := &DB{conn: conn}

	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	if err := db.bootstrapAdminFromEnvironment(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("administrator bootstrap failed: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate creates the schema if it doesn't exist.
func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		username    TEXT    NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		role        TEXT    NOT NULL DEFAULT 'viewer',
		created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
		updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
		last_login  TEXT,
		is_active   INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id         TEXT PRIMARY KEY,
		user_id    INTEGER NOT NULL,
		created_at TEXT    NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT    NOT NULL,
		revoked    INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	`
	_, err := db.conn.Exec(schema)
	return err
}

// bootstrapAdminFromEnvironment creates the first administrator only when the
// database contains no users and both bootstrap environment variables are set.
// The password is never logged.
func (db *DB) bootstrapAdminFromEnvironment() error {
	var count int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	username := strings.TrimSpace(os.Getenv(bootstrapAdminUsernameEnv))
	password := os.Getenv(bootstrapAdminPasswordEnv)

	if username == "" && password == "" {
		log.Printf(
			"TraceSleuth has no users. Set %s and %s before first start to create the initial administrator.",
			bootstrapAdminUsernameEnv,
			bootstrapAdminPasswordEnv,
		)
		return nil
	}

	if username == "" || password == "" {
		return fmt.Errorf("%s and %s must either both be set or both be unset", bootstrapAdminUsernameEnv, bootstrapAdminPasswordEnv)
	}
	if len(password) < minimumPasswordLength {
		return fmt.Errorf("%s must contain at least %d characters", bootstrapAdminPasswordEnv, minimumPasswordLength)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash bootstrap administrator password: %w", err)
	}

	if _, err = db.conn.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, string(hash), string(RoleAdmin),
	); err != nil {
		return fmt.Errorf("failed to insert bootstrap administrator: %w", err)
	}

	log.Printf("TraceSleuth bootstrap administrator %q created successfully; the password was not logged.", username)
	return nil
}

// Authenticate validates credentials and returns the user if valid.
func (db *DB) Authenticate(username, password string) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("account is disabled")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login timestamp.
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.conn.Exec("UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?", now, now, user.ID); err != nil {
		return nil, fmt.Errorf("failed to update last-login timestamp: %w", err)
	}

	return user, nil
}

// GetUserByID retrieves a user by their ID.
func (db *DB) GetUserByID(id int64) (*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return user, nil
}

// CreateUser adds a new user to the database.
func (db *DB) CreateUser(username, password string, role UserRole) (*User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	result, err := db.conn.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		username, string(hash), string(role),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to read created user ID: %w", err)
	}
	return db.getUserByIDUnlocked(id)
}

// getUserByIDUnlocked retrieves a user without acquiring db.mu. Callers must
// already hold the appropriate lock.
func (db *DB) getUserByIDUnlocked(id int64) (*User, error) {
	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.CreatedAt, &user.UpdatedAt, &user.LastLogin, &user.IsActive)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return user, nil
}

// ChangePassword updates a user's password.
func (db *DB) ChangePassword(userID int64, newPassword string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.conn.Exec(
		"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
		string(hash), now, userID,
	)
	return err
}

// ListUsers returns all users (without password hashes in JSON output).
func (db *DB) ListUsers() ([]*User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	rows, err := db.conn.Query(
		"SELECT id, username, password_hash, role, created_at, updated_at, last_login, is_active FROM users ORDER BY id",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin, &u.IsActive); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GenerateSessionID creates a cryptographically random session identifier.
// This legacy helper keeps its string-only signature for compatibility. It
// returns an empty string if the operating system CSPRNG fails; callers must
// reject an empty identifier.
func GenerateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
