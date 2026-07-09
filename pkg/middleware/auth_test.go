package middleware

import (
	"bytes"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/database"
)

func TestNewAuthConfigUsesIndependentRandomSecrets(t *testing.T) {
	first := NewAuthConfig(nil)
	second := NewAuthConfig(nil)

	if len(first.Secret) != 32 {
		t.Fatalf("first JWT secret length = %d, want 32", len(first.Secret))
	}
	if len(second.Secret) != 32 {
		t.Fatalf("second JWT secret length = %d, want 32", len(second.Secret))
	}
	if bytes.Equal(first.Secret, second.Secret) {
		t.Fatal("independent authentication configurations unexpectedly received identical JWT signing secrets")
	}
}

func TestGenerateAndValidateTokenUsesTraceSleuthIssuer(t *testing.T) {
	auth := NewAuthConfig(nil)
	user := &database.User{
		ID:       42,
		Username: "analyst",
		Role:     database.RoleAnalyst,
		IsActive: true,
	}

	token, expiresAt, err := auth.GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned an empty token")
	}
	if expiresAt.IsZero() {
		t.Fatal("GenerateToken() returned a zero expiration time")
	}

	claims, err := auth.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
	if claims.UserID != user.ID {
		t.Fatalf("claims user ID = %d, want %d", claims.UserID, user.ID)
	}
	if claims.Username != user.Username {
		t.Fatalf("claims username = %q, want %q", claims.Username, user.Username)
	}
	if claims.Role != user.Role {
		t.Fatalf("claims role = %q, want %q", claims.Role, user.Role)
	}
	if claims.Issuer != "tracesleuth" {
		t.Fatalf("claims issuer = %q, want %q", claims.Issuer, "tracesleuth")
	}
}

func TestValidateTokenRejectsTokenSignedByDifferentInstance(t *testing.T) {
	issuer := NewAuthConfig(nil)
	validator := NewAuthConfig(nil)
	user := &database.User{
		ID:       7,
		Username: "viewer",
		Role:     database.RoleViewer,
		IsActive: true,
	}

	token, _, err := issuer.GenerateToken(user)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if _, err := validator.ValidateToken(token); err == nil {
		t.Fatal("ValidateToken() accepted a token signed with another random instance secret")
	}
}
