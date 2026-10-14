package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/web/uploadsafe"
	"github.com/google/uuid"
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
	if err := uploadsafe.LimitRequest(c.Writer, c.Request, uploadsafe.MaxComparisonRequestBytes); err != nil {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Comparison upload exceeds request size limit"})
		return
	}
	defer uploadsafe.CleanupMultipart(c.Request)
	// Small memory budget; larger multipart parts spill to temporary disk files.
	if err := c.Request.ParseMultipartForm(8 << 20); err != nil {
		if uploadsafe.IsTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Comparison upload exceeds request size limit"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse upload"})
		}
		return
	}

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

	if headerA.Size > uploadsafe.MaxCaptureBytes || headerB.Size > uploadsafe.MaxCaptureBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Each capture is limited to 500 MiB"})
		return
	}

	tempDir := filepath.Join(h.store.GetUploadsDir(), "compare_"+uuid.New().String())
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tempDir)

	pathA, err := uploadsafe.SaveFileInDir(tempDir, headerA.Filename, fileA, uploadsafe.MaxCaptureBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file_a"})
		return
	}
	pathB, err := uploadsafe.SaveFileInDir(tempDir, headerB.Filename, fileB, uploadsafe.MaxCaptureBytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file_b"})
		return
	}

	var keyLogPath string
	if keyFile, keyHeader, err := c.Request.FormFile("keylog"); err == nil {
		defer keyFile.Close()
		keyExt := strings.ToLower(filepath.Ext(keyHeader.Filename))
		if keyExt != ".log" && keyExt != ".txt" && keyExt != ".keys" && keyExt != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key log extension"})
			return
		}
		if keyHeader.Size > uploadsafe.MaxKeyLogBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Key log exceeds 10 MiB limit"})
			return
		}
		keyLogPath, err = uploadsafe.SaveFileInDir(tempDir, keyHeader.Filename, keyFile, uploadsafe.MaxKeyLogBytes)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save key log"})
			return
		}
	} else if err != http.ErrMissingFile {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key log upload"})
		return
	}

	// Run comparison
	comp := analyzer.NewComparator(false)
	comp.KeyLogPath = keyLogPath
	report, err := comp.Compare(pathA, pathB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Comparison failed: " + err.Error()})
		return
	}

	// Replace temp paths with original filenames in the report
	report.FileA = headerA.Filename
	report.FileB = headerB.Filename

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

