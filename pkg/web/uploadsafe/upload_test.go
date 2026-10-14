package uploadsafe

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveFileInDirOpaqueAndPrivate(t *testing.T) {
	root := t.TempDir()
	path, err := SaveFileInDir(filepath.Join(root, "job"), "../../private.pcap", strings.NewReader("pcap-content"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) == "private.pcap" || filepath.Dir(path) != filepath.Join(root, "job") {
		t.Fatalf("unsafe destination %q", path)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "pcap-content" {
		t.Fatalf("stored contents %q: %v", got, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("upload file not private: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("upload directory not private: info=%v err=%v", info, err)
	}
	if _, err := os.Stat(filepath.Join(root, "private.pcap")); !os.IsNotExist(err) {
		t.Fatalf("wrote outside job directory: %v", err)
	}
}

func TestSaveFileInDirRejectsOversizeWithoutRetainingPartialFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "job")
	_, err := SaveFileInDir(dir, "test.pcap", strings.NewReader("123456"), 5)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("oversize upload retained files: %v, %v", entries, err)
	}
}

func TestSaveFileInDirRejectsUnsupportedFileType(t *testing.T) {
	_, err := SaveFileInDir(t.TempDir(), "evil.sh", strings.NewReader("a"), 10)
	if err == nil {
		t.Fatal("expected unsupported file type failure")
	}
}

func TestLimitRequestKnownAndStreamingBodies(t *testing.T) {
	for _, length := range []int64{5, -1} {
		req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader("12345")))
		req.ContentLength = length
		err := LimitRequest(httptest.NewRecorder(), req, 3)
		if length == 5 {
			if !IsTooLarge(err) {
				t.Fatalf("expected size error for known length: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(req.Body)
			if !IsTooLarge(err) {
				t.Fatalf("expected streaming size error: %v", err)
			}
		}
	}
}
