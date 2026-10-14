package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportArtifactsRollbackOnUncommittedResult(t *testing.T) {
	for _, tc := range []struct {
		name      string
		published bool
	}{
		{"cancelled", false},
		{"completed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "job-results")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			files := newReportArtifacts(dir)
			for _, f := range []string{files.jsonPath, files.htmlPath} {
				if err := os.WriteFile(f, []byte("sensitive report"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			files.published = tc.published
			files.rollbackUnlessPublished()
			for _, f := range []string{files.jsonPath, files.htmlPath} {
				_, err := os.Stat(f)
				if tc.published && err != nil {
					t.Fatalf("published report removed: %v", err)
				}
				if !tc.published && !os.IsNotExist(err) {
					t.Fatalf("unpublished report remained after cancellation: %s, %v", f, err)
				}
			}
		})
	}
}

func TestReportArtifactRollbackDoesNotDeleteOtherFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "job-results")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "unrelated.tmp")
	if err := os.WriteFile(other, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	files := newReportArtifacts(dir)
	if err := os.WriteFile(files.jsonPath, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	files.rollbackUnlessPublished()
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("rollback removed an unrelated file: %v", err)
	}
}
