package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadCannotTraverseViaClientFilename(t *testing.T) {
	router, _, store := setupTestRouter(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "../../escape.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(buildMinimalPCAP()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("upload status: %d %s", res.Code, res.Body.String())
	}
	files, err := os.ReadDir(store.GetUploadsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("expected private job subdirectory")
	}
	if _, err := os.Stat(filepath.Join(store.GetUploadsDir(), "escape.pcap")); !os.IsNotExist(err) {
		t.Fatalf("client path escaped job scope: %v", err)
	}
}

func TestUploadRejectsOversizedHTTPBodyBeforeParsing(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", strings.NewReader("x"))
	req.ContentLength = 600 << 20
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d: %s", res.Code, res.Body.String())
	}
}
