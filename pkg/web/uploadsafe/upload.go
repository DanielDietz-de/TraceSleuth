// Package uploadsafe centralizes bounded, opaque storage of untrusted web uploads.
package uploadsafe

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const (
	MaxCaptureBytes           = int64(500 << 20)
	MaxKeyLogBytes            = int64(10 << 20)
	multipartOverheadBytes    = int64(1 << 20)
	MaxSingleRequestBytes     = MaxCaptureBytes + MaxKeyLogBytes + multipartOverheadBytes
	MaxComparisonRequestBytes = 2*MaxCaptureBytes + MaxKeyLogBytes + multipartOverheadBytes
)

var ErrTooLarge = errors.New("upload exceeds size limit")

// LimitRequest enforces the whole multipart request limit, not just the
// in-memory ParseMultipartForm threshold. Unknown content lengths are bounded
// while reading, and known oversized bodies are rejected immediately.
func LimitRequest(w http.ResponseWriter, r *http.Request, max int64) error {
	if r.ContentLength > max {
		return ErrTooLarge
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	return nil
}

func IsTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.Is(err, ErrTooLarge) || errors.As(err, &maxErr)
}

func CleanupMultipart(r *http.Request) {
	if r.MultipartForm != nil {
		_ = r.MultipartForm.RemoveAll()
	}
}

// SaveFileInDir never uses the untrusted client name as a filesystem path.
// The name's extension is accepted only for supported capture/keylog types;
// O_EXCL, private permissions and a streaming byte ceiling protect writes.
func SaveFileInDir(dir, originalName string, input io.Reader, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		return "", fmt.Errorf("invalid upload limit")
	}
	ext := strings.ToLower(filepath.Ext(originalName))
	switch ext {
	case ".pcap", ".pcapng", ".cap", ".log", ".txt", ".keys", "":
	default:
		return "", fmt.Errorf("unsupported upload extension")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create upload directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("secure upload directory: %w", err)
	}
	dst := filepath.Join(dir, uuid.NewString()+ext)
	file, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("create private upload file: %w", err)
	}
	n, copyErr := io.Copy(file, io.LimitReader(input, maxBytes+1))
	if copyErr == nil && n > maxBytes {
		copyErr = ErrTooLarge
	}
	if closeErr := file.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(dst)
		return "", fmt.Errorf("write upload: %w", copyErr)
	}
	return dst, nil
}
