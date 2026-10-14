package handlers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
)

func TestDisplayFileNameRejectsPathAndHeaderInjection(t *testing.T) {
	tests := map[string]string{
		"../../secrets.pcap":         "secrets.pcap",
		"C:\\tmp\\capture.pcap":      "capture.pcap",
		"report\r\nInjected: x.pcap": "reportInjected: x.pcap",
	}
	for input, want := range tests {
		if got := displayFileName(input); got != want {
			t.Errorf("displayFileName(%q) = %q, want %q", input, got, want)
		}
	}
	if strings.ContainsAny(attachmentName("name\r\nHeader: x.pcap"), "\r\n") {
		t.Fatal("header injection in attachment disposition")
	}
}

func TestWebSocketOriginMustMatchRequestHostExactly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/ws/a", nil)
	for _, test := range []struct {
		origin string
		want   bool
	}{
		{"http://localhost:8080", true},
		{"https://localhost:8080", true},
		{"http://localhost.attacker.test:8080", false},
		{"http://127.0.0.1:8080", false},
		{"http://localhost:9999", false},
		{"", false},
		{"file:///localhost:8080", false},
	} {
		req.Header.Set("Origin", test.origin)
		if got := sameOriginWebSocket(req); got != test.want {
			t.Errorf("origin %q matched = %v, want %v", test.origin, got, test.want)
		}
	}
}

func TestMultipartBoundEnforcedOnActualStream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/", func(c *gin.Context) {
		if err := parseUpload(c, 64); err != nil {
			rejectUploadError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	})
	for _, contentLength := range []int64{-1, 128} {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("a"), 128)))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
		req.ContentLength = contentLength
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("ContentLength=%d: status = %d, want 413", contentLength, w.Code)
		}
	}
}

func TestComparisonTempFilesArePrivateAndBounded(t *testing.T) {
	dir := t.TempDir()
	path, err := saveComparisonFile(strings.NewReader("pcap"), dir, "capture-a-", 4)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("temp file escaped directory: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file permissions = %o, want 0600", info.Mode().Perm())
	}
	p, err := saveComparisonFile(strings.NewReader("12345"), dir, "capture-b-", 4)
	if p != "" || !errors.Is(err, storage.ErrUploadTooLarge) {
		t.Fatalf("oversize comparison: path=%q err=%v", p, err)
	}
}
