package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestWebSocketBearerTokenNotFromURL(t *testing.T) {
	request := httptest.NewRequest("GET", "http://localhost:8080/api/ws/id?token=secret", nil)
	if token := WebSocketBearerToken(request); token != "" {
		t.Fatalf("JWT was read from URL: %q", token)
	}
	request.Header.Set("Sec-WebSocket-Protocol", "tracesleuth.jwt.abc.def.ghi")
	if token := WebSocketBearerToken(request); token != "abc.def.ghi" {
		t.Fatalf("expected protocol JWT, got %q", token)
	}
	request.Header.Add("Sec-WebSocket-Protocol", "tracesleuth.jwt.other")
	if token := WebSocketBearerToken(request); token != "" {
		t.Fatal("accepted ambiguous credentials")
	}
}

func TestWebSocketOriginRejectsCrossSiteAndPrefixImpersonation(t *testing.T) {
	for _, test := range []struct {
		origin string
		pass   bool
	}{
		{"http://localhost:8080", true},
		{"http://localhost.attacker.test:8080", false},
		{"http://localhost:8080.attacker.test", false},
		{"https://evil.example", false},
		{"http://localhost:9090", false},
		{"https://localhost:8080/other", false},
	} {
		r := httptest.NewRequest("GET", "http://localhost:8080/api/ws/id", nil)
		r.Header.Set("Origin", test.origin)
		if got := SameOriginWebSocket(r); got != test.pass {
			t.Errorf("origin %q: want %v got %v", test.origin, test.pass, got)
		}
	}
	if AllowLoopbackCORS("http://localhost.attacker.test") {
		t.Fatal("CORS accepted a deceptive localhost prefix")
	}
	if !AllowLoopbackCORS("http://127.0.0.1:3000") {
		t.Fatal("legitimate loopback frontend rejected")
	}
}
