package database

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "tracesleuth-test.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return db
}

func TestOpenDoesNotCreateUniversalDefaultAdministrator(t *testing.T) {
	t.Setenv(bootstrapAdminUsernameEnv, "")
	t.Setenv(bootstrapAdminPasswordEnv, "")

	db := openTestDB(t)
	users, err := db.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("ListUsers() returned %d user(s), want 0; TraceSleuth must not create a universal default administrator", len(users))
	}
}

func TestOpenBootstrapsExplicitAdministratorWithoutDefaultCredentials(t *testing.T) {
	const (
		username = "bootstrap-admin"
		password = "correct-horse-battery-staple"
	)
	t.Setenv(bootstrapAdminUsernameEnv, username)
	t.Setenv(bootstrapAdminPasswordEnv, password)

	db := openTestDB(t)
	users, err := db.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers() returned %d user(s), want 1", len(users))
	}
	if users[0].Username != username {
		t.Fatalf("bootstrap username = %q, want %q", users[0].Username, username)
	}
	if users[0].Role != RoleAdmin {
		t.Fatalf("bootstrap role = %q, want %q", users[0].Role, RoleAdmin)
	}
	if users[0].PasswordHash == password {
		t.Fatal("bootstrap password was stored in plaintext")
	}

	authenticated, err := db.Authenticate(username, password)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated.Username != username {
		t.Fatalf("authenticated username = %q, want %q", authenticated.Username, username)
	}

	if _, err := db.Authenticate("admin", "admin"); err == nil {
		t.Fatal("inherited universal admin/admin credential unexpectedly authenticates")
	}
}

func TestOpenRejectsPartialBootstrapConfiguration(t *testing.T) {
	t.Setenv(bootstrapAdminUsernameEnv, "bootstrap-admin")
	t.Setenv(bootstrapAdminPasswordEnv, "")

	_, err := Open(filepath.Join(t.TempDir(), "partial-bootstrap.db"))
	if err == nil {
		t.Fatal("Open() succeeded with only one bootstrap environment variable, want error")
	}
}

func TestOpenRejectsWeakBootstrapPassword(t *testing.T) {
	t.Setenv(bootstrapAdminUsernameEnv, "bootstrap-admin")
	t.Setenv(bootstrapAdminPasswordEnv, "too-short")

	_, err := Open(filepath.Join(t.TempDir(), "weak-bootstrap.db"))
	if err == nil {
		t.Fatal("Open() succeeded with weak bootstrap password, want error")
	}
}

func TestCreateUserDoesNotDeadlock(t *testing.T) {
	t.Setenv(bootstrapAdminUsernameEnv, "")
	t.Setenv(bootstrapAdminPasswordEnv, "")
	db := openTestDB(t)

	done := make(chan error, 1)
	go func() {
		_, err := db.CreateUser("analyst", "a-strong-test-password", RoleAnalyst)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CreateUser() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CreateUser() timed out; possible nested-lock deadlock")
	}
}
