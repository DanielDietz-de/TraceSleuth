package handlers

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/DanielDietz-de/TraceSleuth/pkg/analyzer"
	"github.com/DanielDietz-de/TraceSleuth/pkg/web/storage"
	"github.com/gin-gonic/gin"
)

// ComparisonHandlers provides endpoints for PCAP comparison mode
type ComparisonHandlers struct {
	store interface {
		GetUploadsDir() string
	}
}

// NewComparisonHandlers creates a new comparison handler.
// Accepts any store that provides GetUploadsDir().
func NewComparisonHandlers(uploadsDir string) *ComparisonHandlers {
	return &ComparisonHandlers{
		store: &simpleUploadsDir{dir: uploadsDir},
	}
}

type simpleUploadsDir struct{ dir string }

func (s *simpleUploadsDir) GetUploadsDir() string { return s.dir }

// PostCompareUpload handles the comparison of two uploaded PCAP files.
// POST /api/compare-pcap  (multipart: file_a, file_b)
func (h *ComparisonHandlers) PostCompareUpload(c *gin.Context) {
	// Each capture is limited to 200 MiB; the combined request also allows
	// an optional 8 MiB key log and bounded multipart framing overhead.
	if err := parseUpload(c, 2*maxCompareFileBytes+storage.MaxKeyLogBytes+multipartOverhead); err != nil {
		rejectUploadError(c, err)
		return
	}
	defer c.Request.MultipartForm.RemoveAll()

	// Get file A (LAN-side)
	fileA, headerA, err := c.Request.FormFile("file_a")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing file_a (LAN-side capture)"})
		return
	}
	defer fileA.Close()

	// Get file B (WAN-side)
	fileB, headerB, err := c.Request.FormFile("file_b")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing file_b (WAN-side capture)"})
		return
	}
	defer fileB.Close()

	// Validate extensions
	for _, hdr := range []struct {
		name string
		ext  string
	}{
		{"file_a", strings.ToLower(filepath.Ext(headerA.Filename))},
		{"file_b", strings.ToLower(filepath.Ext(headerB.Filename))},
	} {
		if hdr.ext != ".pcap" && hdr.ext != ".pcapng" && hdr.ext != ".cap" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("%s has invalid extension '%s' (must be .pcap, .pcapng, or .cap)", hdr.name, hdr.ext),
			})
			return
		}
	}

	if headerA.Size > maxCompareFileBytes || headerB.Size > maxCompareFileBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Each comparison capture must be at most 200 MiB"})
		return
	}
	if headerA.Size == 0 || headerB.Size == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Comparison captures must not be empty"})
		return
	}

	// CreateTemp never interprets client-supplied path separators or names.
	tempDir, err := os.MkdirTemp(h.store.GetUploadsDir(), "compare-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare comparison"})
		return
	}
	defer os.RemoveAll(tempDir)

	pathA, err := saveComparisonFile(fileA, tempDir, "capture-a-", maxCompareFileBytes)
	if err != nil {
		rejectComparisonSave(c, err)
		return
	}
	pathB, err := saveComparisonFile(fileB, tempDir, "capture-b-", maxCompareFileBytes)
	if err != nil {
		rejectComparisonSave(c, err)
		return
	}

	// Key log content is sensitive and must remain private, temporary and bounded.
	var keyLogPath string
	if keyFile, keyHeader, err := c.Request.FormFile("keylog"); err == nil {
		defer keyFile.Close()
		keyExt := strings.ToLower(filepath.Ext(keyHeader.Filename))
		if keyExt != ".log" && keyExt != ".txt" && keyExt != "" && keyExt != ".keys" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key log extension"})
			return
		}
		if keyHeader.Size > storage.MaxKeyLogBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Key log exceeds 8 MiB limit"})
			return
		}
		keyLogPath, err = saveComparisonFile(keyFile, tempDir, "keylog-", storage.MaxKeyLogBytes)
		if err != nil {
			rejectComparisonSave(c, err)
			return
		}
	} else if !errors.Is(err, http.ErrMissingFile) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key log attachment"})
		return
	}

	// Run comparison
	comp := analyzer.NewComparator(false)
	comp.KeyLogPath = keyLogPath
	report, err := comp.Compare(pathA, pathB)
	if err != nil {
		// Keep server-owned randomized temp paths out of response bodies.
		// Malformed packet errors carry a safe index and parser cause.
		var malformed *analyzer.MalformedCaptureRecordError
		if errors.As(err, &malformed) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Comparison failed: " + malformed.Error()})
		} else {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Comparison failed: invalid or unreadable capture"})
		}
		return
	}

	// Replace temp paths with original filenames in the report
	report.FileA = displayFileName(headerA.Filename)
	report.FileB = displayFileName(headerB.Filename)

	c.JSON(http.StatusOK, report)
}

// PostCompareJobs compares two already-analyzed jobs by their PCAP files.
// POST /api/compare-jobs  { "job_a": "uuid", "job_b": "uuid" }
// This reuses PCAPs that were already uploaded for analysis.
func (h *ComparisonHandlers) PostCompareJobs(c *gin.Context) {
	// This endpoint needs access to the full storage to look up jobs.
	// It's a simpler alternative — documented but not wired until storage is injected.
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Use /api/compare-pcap with direct file uploads"})
}

func saveComparisonFile(src io.Reader, directory, prefix string, limit int64) (string, error) {
	file, err := os.CreateTemp(directory, prefix+"*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	written, copyErr := io.Copy(file, io.LimitReader(src, limit+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > limit {
		os.Remove(path)
		switch {
		case written > limit:
			return "", storage.ErrUploadTooLarge
		case copyErr != nil:
			return "", copyErr
		default:
			return "", closeErr
		}
	}
	return path, nil
}

func rejectComparisonSave(c *gin.Context, err error) {
	if errors.Is(err, storage.ErrUploadTooLarge) {
		rejectUploadError(c, err)
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store comparison upload"})
}
