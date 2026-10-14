package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
)

// Parsing into memory is capped separately from the total HTTP body. Multipart
// limits must be installed on the body BEFORE FormFile or ParseMultipartForm.
const (
	maxMultipartMemory  int64 = 16 << 20
	multipartOverhead   int64 = 1 << 20
	maxCompareFileBytes int64 = 200 << 20
)

func parseUpload(c *gin.Context, totalBytes int64) error {
	if c.Request.ContentLength > totalBytes {
		return &http.MaxBytesError{Limit: totalBytes}
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, totalBytes)
	err := c.Request.ParseMultipartForm(maxMultipartMemory)
	// net/http can populate MultipartForm and write multipart-* temp files even
	// when ParseForm (e.g. a malformed query string) returns an error. Cleanup
	// cannot be deferred solely by the caller after a successful parse.
	if err != nil && c.Request.MultipartForm != nil {
		_ = c.Request.MultipartForm.RemoveAll()
		c.Request.MultipartForm = nil
	}
	return err
}

func rejectUploadError(c *gin.Context, err error) {
	var sizeError *http.MaxBytesError
	if errors.As(err, &sizeError) || errors.Is(err, storage.ErrUploadTooLarge) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Upload exceeds size limit"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid multipart upload"})
}

// displayFileName is used only for presentation, never as a storage path.
// Normalize separators on all host operating systems and strip controls.
func displayFileName(input string) string {
	input = path.Base(strings.ReplaceAll(input, "\\", "/"))
	var name strings.Builder
	for _, r := range input {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			continue
		}
		if name.Len()+len(string(r)) > 200 {
			break
		}
		name.WriteRune(r)
	}
	result := strings.TrimSpace(name.String())
	if result == "" || result == "." || result == ".." {
		return "capture"
	}
	return result
}

// attachmentName generates a standards-encoded attachment disposition.
// It prevents CRLF/header injection even for legacy job display names.
func attachmentName(filename string) string {
	name := displayFileName(filename)
	return fmt.Sprintf("attachment; filename=%q", name)
}
