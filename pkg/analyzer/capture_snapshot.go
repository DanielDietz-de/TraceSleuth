package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Snapshotting separates the untrusted, potentially changing input inode
// from decoder memory allocations. ReadAt framing validation and packet
// decoding operate exclusively on the same private working bytes.
// This limit is intentionally explicit until configurable disk quotas and
// global analysis concurrency are implemented in Phase 9.
const maxSnapshotBytes int64 = 4 << 30

// openImmutableCapture copies the source descriptor into a private 0600
// temporary file, computes the actual working-copy digest in the same pass,
// and keeps the original descriptor for post-analysis mutation detection.
//
// The original path is opened once; atomic pathname replacements cannot
// redirect the copy. A modification during the copy is detected when the
// original descriptor is rehashed before analysis succeeds. Failed copies
// always clean up their temporary file and both descriptors.
func openImmutableCapture(path string) (*CaptureHandle, string, int64, error) {
	source, err := os.Open(path)
	if err != nil {
		return nil, "", 0, fmt.Errorf("open capture: %w", err)
	}
	sourceInfo, err := source.Stat()
	if err != nil {
		source.Close()
		return nil, "", 0, fmt.Errorf("stat source capture: %w", err)
	}
	if sourceInfo.Mode().IsRegular() && sourceInfo.Size() > maxSnapshotBytes {
		source.Close()
		return nil, "", 0, fmt.Errorf("capture exceeds %d-byte analysis working-copy limit", maxSnapshotBytes)
	}
	working, err := os.CreateTemp("", "tracesleuth-capture-*")
	if err != nil {
		source.Close()
		return nil, "", 0, fmt.Errorf("create private capture working copy: %w", err)
	}
	handle := &CaptureHandle{
		File:         working,
		SourceFile:   source,
		snapshotPath: working.Name(),
	}
	fail := func(err error) (*CaptureHandle, string, int64, error) {
		_ = handle.Close()
		return nil, "", 0, err
	}

	// LimitReader applies to non-regular input as well. The extra byte
	// distinguishes an exact-limit file from an over-limit stream.
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(working, hash), io.LimitReader(source, maxSnapshotBytes+1))
	if err != nil {
		return fail(fmt.Errorf("copy source capture into private working file: %w", err))
	}
	if size > maxSnapshotBytes {
		return fail(fmt.Errorf("capture exceeds %d-byte analysis working-copy limit", maxSnapshotBytes))
	}
	if _, err := working.Seek(0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("rewind immutable capture working copy: %w", err))
	}
	return handle, hex.EncodeToString(hash.Sum(nil)), size, nil
}

// Close releases private working storage even if the parser or analysis
// returns an error. A close failure must not skip the remaining cleanup.
func (h *CaptureHandle) Close() error {
	if h == nil {
		return nil
	}
	var errs []error
	if h.File != nil {
		if err := h.File.Close(); err != nil {
			errs = append(errs, err)
		}
		h.File = nil
	}
	if h.SourceFile != nil {
		if err := h.SourceFile.Close(); err != nil {
			errs = append(errs, err)
		}
		h.SourceFile = nil
	}
	if h.snapshotPath != "" {
		if err := os.Remove(h.snapshotPath); err != nil {
			errs = append(errs, err)
		}
		h.snapshotPath = ""
	}
	return errors.Join(errs...)
}
