package handlers

import (
	"bytes"
	"encoding/binary"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The web API must not leak private server-side comparison temp paths when
// an uploaded capture has a truncated packet record.
func TestCompareUploadMalformedRecordDoesNotExposeServerPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	uploads := t.TempDir()
	router := gin.New()
	router.POST("/api/compare-pcap", NewComparisonHandlers(uploads).PostCompareUpload)

	valid := buildMinimalPCAP()
	broken := append([]byte(nil), valid...)
	next := make([]byte, 16)
	binary.LittleEndian.PutUint32(next[8:12], 54)
	binary.LittleEndian.PutUint32(next[12:16], 54)
	broken = append(broken, next...)
	broken = append(broken, []byte("partial")...)

	var form bytes.Buffer
	writer := multipart.NewWriter(&form)
	for _, part := range []struct {
		name string
		data []byte
	}{
		{"file_a", valid},
		{"file_b", broken},
	} {
		f, err := writer.CreateFormFile(part.name, part.name+".pcap")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(f, bytes.NewReader(part.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/compare-pcap", &form)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("HTTP %d, expected 422: %s", recorder.Code, recorder.Body.String())
	}
	response := recorder.Body.String()
	if !strings.Contains(response, "index 1") {
		t.Fatalf("missing safe packet index in error: %s", response)
	}
	if strings.Contains(response, uploads) || strings.Contains(response, "compare-") {
		t.Fatalf("internal comparison temp path leaked: %s", response)
	}
	items, err := os.ReadDir(uploads)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("comparison left %d temporary directories", len(items))
	}
}
