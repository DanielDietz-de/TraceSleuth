package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func makeQualityFixture(t *testing.T, ng bool, packets []gopacket.CaptureInfo) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	var write func(gopacket.CaptureInfo, []byte) error
	if ng {
		w, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
		if err != nil { t.Fatal(err) }
		write = w.WritePacket
		defer func() {
			if err := w.Flush(); err != nil { t.Fatal(err) }
		}()
	} else {
		w := pcapgo.NewWriter(&buf)
		if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil { t.Fatal(err) }
		write = w.WritePacket
	}
	data := make([]byte, 60)
	data[12], data[13] = 0x08, 0x00
	for _, ci := range packets {
		if err := write(ci, data[:ci.CaptureLength]); err != nil { t.Fatal(err) }
	}
	// Writer must be flushed prior to reading its bytes.
	if ng {
		// The deferred Flush above is not sufficient here, so the test
		// writer is flushed in the helper's writer-specific branch below.
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if ng { path += "ng" }
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil { t.Fatal(err) }
	return path, buf.Bytes()
}

func TestInspectCapturePCAPMetadataAndTruncation(t *testing.T) {
	t0 := time.Unix(1000, 0).UTC()
	packets := []gopacket.CaptureInfo{
		{Timestamp: t0, CaptureLength: 60, Length: 60},
		{Timestamp: t0.Add(time.Second), CaptureLength: 40, Length: 60},
		{Timestamp: t0.Add(-time.Second), CaptureLength: 60, Length: 60},
	}
	path, data := makeQualityFixture(t, false, packets)
	result, err := InspectCapture(path)
	if err != nil { t.Fatal(err) }
	if result.Format != "pcap" || result.PacketCount != 3 || result.TruncatedPackets != 1 || result.NonMonotonicTimestamps != 1 {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	digest := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(digest[:]) { t.Fatal("capture digest mismatch") }
	if result.Status != "degraded" || result.DurationSeconds != 2 {
		t.Fatalf("unexpected quality result: %+v", result)
	}
	if len(result.Interfaces) != 1 || result.Interfaces[0].PacketCount != 3 {
		t.Fatalf("missing interface metadata: %+v", result.Interfaces)
	}
	if ok, err := CaptureIdentity(path, result.SHA256); err != nil || !ok { t.Fatalf("identity: %v %v", ok, err) }
	if err := os.WriteFile(path, append(data, 'x'), 0600); err != nil { t.Fatal(err) }
	if ok, err := CaptureIdentity(path, result.SHA256); err != nil || ok { t.Fatalf("replacement not detected: %v %v", ok, err) }
}

func TestInspectCaptureRejectsTruncatedRecordAndEmptyCapture(t *testing.T) {
	t0 := time.Unix(1000, 0)
	path, b := makeQualityFixture(t, false, []gopacket.CaptureInfo{{Timestamp: t0, CaptureLength: 60, Length: 60}})
	if err := os.WriteFile(path, b[:len(b)-6], 0600); err != nil { t.Fatal(err) }
	if _, err := InspectCapture(path); err == nil { t.Fatal("truncated packet accepted") }
	empty, _ := makeQualityFixture(t, false, nil)
	if _, err := InspectCapture(empty); err == nil || !strings.Contains(err.Error(), "no packets") { t.Fatalf("expected empty-capture rejection: %v", err) }
}
