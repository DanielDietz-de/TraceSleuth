package analyzer

import (
	"os"
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// A same-size, in-place rewrite of the source after the snapshot was created
// must not let the third-party decoder observe attacker-controlled bytes.
// Post-analysis verification still detects that the submitted source changed.
func TestCaptureDecoderUsesImmutableSnapshotDespiteSourceRewrite(t *testing.T) {
	for _, ng := range []bool{true, false} {
		t.Run(map[bool]string{true: "pcapng", false: "pcap"}[ng], func(t *testing.T) {
			path, data := makeQualityFixture(t, ng, []gopacket.CaptureInfo{{
				Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
			}})
			handle, digest, size, err := openImmutableCapture(path)
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
			workingName := handle.snapshotPath
			if workingName == "" || workingName == path {
				t.Fatal("decoder has no separate private working copy")
			}
			st, err := os.Stat(workingName)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0600 {
				t.Fatalf("working copy permissions %04o, want 0600", st.Mode().Perm())
			}
			// Overwrite the original inode with invalid parser bytes, without
			// changing its length. A live ReaderAt would now decode a different
			// header or a malicious packet allocation.
			if err := os.WriteFile(path, make([]byte, len(data)), 0600); err != nil {
				t.Fatal(err)
			}
			parsed, err := openCaptureOnFile(handle.File, pcapgo.NgReaderOptions{WantMixedLinkType: true})
			if err != nil {
				t.Fatalf("immutable snapshot was affected by source rewrite: %v", err)
			}
			handle.Reader, handle.Format = parsed.Reader, parsed.Format
			if _, _, err := handle.Reader.ReadPacketData(); err != nil {
				t.Fatalf("snapshot packet vanished after source rewrite: %v", err)
			}
			quality := &models.CaptureQuality{SHA256: digest, FileSizeBytes: size}
			if err := VerifyCaptureHandle(handle, quality); err == nil {
				t.Fatal("post-analysis verification accepted a modified submitted capture")
			}
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(workingName); !os.IsNotExist(err) {
				t.Fatalf("private working file not removed after close: %v", err)
			}
		})
	}
}

func TestOpenCaptureReturnsPrivateWorkingCopyAndCleansIt(t *testing.T) {
	path, _ := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(999, 0), CaptureLength: 60, Length: 60,
	}})
	handle, err := OpenCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	name := handle.snapshotPath
	if name == "" || handle.SourceFile == nil {
		t.Fatal("OpenCapture failed to bind its immutable working copy")
	}
	if _, _, err := handle.Reader.ReadPacketData(); err != nil {
		t.Fatalf("cannot read validated snapshot: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("working copy leaked after Close: %v", err)
	}
}
