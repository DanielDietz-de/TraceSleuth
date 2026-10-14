package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testUploadStorage(t *testing.T) *Storage {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	store, err := NewStorage()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSaveUploadedFileUsesPrivateRandomPath(t *testing.T) {
	store := testUploadStorage(t)
	id := uuid.NewString()
	path, err := store.SaveUploadedFile(id, strings.NewReader("sample pcap bytes"), "../../outside.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != filepath.Join(store.GetUploadsDir(), id) {
		t.Fatalf("unmanaged upload path: %s", path)
	}
	if strings.Contains(path, "outside") {
		t.Fatalf("untrusted filename leaked into path: %s", path)
	}
	for _, pathname := range []string{store.GetDataDir(), store.GetUploadsDir(), filepath.Dir(path)} {
		info, err := os.Stat(pathname)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("%s permissions = %o, want 0700", pathname, info.Mode().Perm())
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("uploaded file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestSaveUploadedFileEnforcesActualBytesAndCleansPartial(t *testing.T) {
	store := testUploadStorage(t)
	id := uuid.NewString()
	path, err := store.SaveUploadedFileLimited(id, bytes.NewReader([]byte("abcd")), 3)
	if path != "" || !errors.Is(err, ErrUploadTooLarge) {
		t.Fatalf("oversize upload: path %q, err %v", path, err)
	}
	files, err := os.ReadDir(filepath.Join(store.GetUploadsDir(), id))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("partial upload left %d files", len(files))
	}
	path, err = store.SaveUploadedFileLimited(id, strings.NewReader("abc"), 3)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "abc" {
		t.Fatalf("unexpected saved content %q: %v", data, err)
	}
	if _, err := store.SaveUploadedFileLimited("../unsafe", strings.NewReader("x"), 3); err == nil {
		t.Fatal("accepted unsafe job ID")
	}
}

func TestManagedFileContainmentRejectsTraversalAndPrefix(t *testing.T) {
	root := filepath.Join(t.TempDir(), "results")
	for _, path := range []string{
		filepath.Join(root, "..", "secrets.txt"),
		root + "-other/job/output.json",
		root,
	} {
		if isManagedFile(root, path) {
			t.Fatalf("accepted unmanaged path %q", path)
		}
	}
	if !isManagedFile(root, filepath.Join(root, "job", "report.json")) {
		t.Fatal("rejected managed path")
	}
}

func TestStorageRejectsUnmanagedResultAndDeletion(t *testing.T) {
	store := testUploadStorage(t)
	id := uuid.NewString()
	job, err := store.CreateJob(id, "test.pcap", 4, "")
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(outside, []byte("must not delete"), 0600); err != nil {
		t.Fatal(err)
	}
	job.ResultsPath = outside
	if err := store.UpdateJob(job); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetResultsFile(id, "json"); err == nil {
		t.Fatal("served a results path outside managed storage")
	}
	if path := store.GetResultsPath(id); path != "" {
		t.Fatalf("unmanaged results path leaked through compatibility accessor: %s", path)
	}
	if err := store.DeleteJob(id); err == nil {
		t.Fatal("deleted a job with unmanaged persisted file paths")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("unmanaged file modified/deleted: %v", err)
	}
}

func TestKeyLogMetadataRoundTripAndDeletion(t *testing.T) {
	store := testUploadStorage(t)
	id := uuid.NewString()
	capture, err := store.SaveUploadedFile(id, strings.NewReader("pcap"), "pcap")
	if err != nil {
		t.Fatal(err)
	}
	keylog, err := store.SaveUploadedFileLimited(id, strings.NewReader("sensitive"), MaxKeyLogBytes)
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.CreateJob(id, "capture.pcap", 4, capture)
	if err != nil {
		t.Fatal(err)
	}
	job.KeyLogPath = keylog
	if err := store.UpdateJob(job); err != nil {
		t.Fatal(err)
	}
	reloaded, err := store.GetJob(id)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.KeyLogPath != keylog {
		t.Fatalf("lost keylog path across storage roundtrip: %q", reloaded.KeyLogPath)
	}
	if err := store.DeleteJob(id); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{capture, keylog} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("sensitive file %s still exists: %v", path, err)
		}
	}
}
