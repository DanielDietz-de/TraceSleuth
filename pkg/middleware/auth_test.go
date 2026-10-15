package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/DanielDietz-de/TraceSleuth/pkg/database"
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

func TestWebSocketSubprotocolTokenAllowedOnlyDuringUpgrade(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/ws/:id", func(c *gin.Context) {
		c.String(http.StatusOK, webSocketHandshakeToken(c))
	})
	router.GET("/api/status", func(c *gin.Context) {
		c.String(http.StatusOK, webSocketHandshakeToken(c))
	})
	for _, tc := range []struct {
		path, upgrade, protocol, want string
	}{
		{"/api/ws/1", "websocket", "tracesleuth.jwt.abc.def.sig", "abc.def.sig"},
		{"/api/ws/1?token=leaked", "websocket", "", ""},
		{"/api/ws/1", "", "tracesleuth.jwt.abc", ""},
		{"/api/status", "websocket", "tracesleuth.jwt.abc", ""},
		{"/api/ws/1", "websocket", "unrelated", ""},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Upgrade", tc.upgrade)
		req.Header.Set("Sec-WebSocket-Protocol", tc.protocol)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Body.String() != tc.want {
			t.Errorf("%q / %q / %q returned %q, want %q", tc.path, tc.upgrade, tc.protocol, w.Body.String(), tc.want)
		}
	}
}

func TestRequireAuthRejectsQueryToken(t *testing.T) {
	auth := NewAuthConfig(nil)
	router := gin.New()
	router.GET("/api/status", auth.RequireAuth(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	token, _, err := auth.GenerateToken(&database.User{ID: 12, Username: "user", Role: database.RoleAnalyst})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/status?token="+token, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("query token accepted: status %d", w.Code)
	}
}
