package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

const wsAuthPrefix = "tracesleuth.jwt."

// WebSocketBearerToken retrieves a browser JWT exclusively from the
// Sec-WebSocket-Protocol request header, never from URLs. Gorilla's upgrader
// must not echo this credential as an agreed response subprotocol.
func WebSocketBearerToken(r *http.Request) string {
	var token string
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(header, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.HasPrefix(protocol, wsAuthPrefix) {
				continue
			}
			value := strings.TrimPrefix(protocol, wsAuthPrefix)
			if value == "" || token != "" {
				return ""
			}
			token = value
		}
	}
	return token
}

// AllowLoopbackCORS permits local frontend development origins without
// accepting attacker-controlled hosts such as localhost.evil.example.
func AllowLoopbackCORS(origin string) bool {
	parsed, ok := parseOrigin(origin)
	if !ok {
		return false
	}
	switch strings.ToLower(parsed.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

// SameOriginWebSocket rejects cross-origin browser WebSocket handshakes.
// Non-browser clients that omit Origin still require a valid bearer token.
func SameOriginWebSocket(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, ok := parseOrigin(origin)
	return ok && strings.EqualFold(parsed.Host, r.Host)
}

func parseOrigin(origin string) (*url.URL, bool) {
	u, err := url.Parse(origin)
	if err != nil || u == nil {
		return nil, false
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" ||
		u.Fragment != "" || u.Opaque != "" {
		return nil, false
	}
	return u, true
}
