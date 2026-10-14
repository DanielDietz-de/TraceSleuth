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
	var flush func() error
	if ng {
		w, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		write = w.WritePacket
		flush = w.Flush
	} else {
		w := pcapgo.NewWriter(&buf)
		if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
		write = w.WritePacket
	}
	data := make([]byte, 60)
	data[12], data[13] = 0x08, 0x00
	for _, ci := range packets {
		if err := write(ci, data[:ci.CaptureLength]); err != nil {
			t.Fatal(err)
		}
	}
	// Pcapng buffers blocks internally; flush before persisting the fixture.
	if flush != nil {
		if err := flush(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if ng {
		path += "ng"
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "pcap" || result.PacketCount != 3 || result.TruncatedPackets != 1 || result.NonMonotonicTimestamps != 1 {
		t.Fatalf("unexpected metadata: %+v", result)
	}
	digest := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("capture digest mismatch")
	}
	if result.Status != "degraded" || result.DurationSeconds != 2 {
		t.Fatalf("unexpected quality result: %+v", result)
	}
	if len(result.Interfaces) != 1 || result.Interfaces[0].PacketCount != 3 {
		t.Fatalf("missing interface metadata: %+v", result.Interfaces)
	}
	if ok, err := CaptureIdentity(path, result.SHA256); err != nil || !ok {
		t.Fatalf("identity: %v %v", ok, err)
	}
	if err := os.WriteFile(path, append(data, 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := CaptureIdentity(path, result.SHA256); err != nil || ok {
		t.Fatalf("replacement not detected: %v %v", ok, err)
	}
}

func TestInspectCaptureRejectsTruncatedRecordAndEmptyCapture(t *testing.T) {
	t0 := time.Unix(1000, 0)
	path, b := makeQualityFixture(t, false, []gopacket.CaptureInfo{{Timestamp: t0, CaptureLength: 60, Length: 60}})
	if err := os.WriteFile(path, b[:len(b)-6], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil {
		t.Fatal("truncated packet accepted")
	}
	empty, _ := makeQualityFixture(t, false, nil)
	if _, err := InspectCapture(empty); err == nil || !strings.Contains(err.Error(), "no packets") {
		t.Fatalf("expected empty-capture rejection: %v", err)
	}
}

func TestInspectCapturePCAPNGInterfaceMetadata(t *testing.T) {
	t0 := time.Unix(10, 0).UTC()
	path, _ := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: t0, CaptureLength: 60, Length: 60,
	}})
	quality, err := InspectCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	if quality.Format != "pcapng" || quality.Status != "good" || quality.PacketCount != 1 ||
		len(quality.Interfaces) != 1 || quality.Interfaces[0].PacketCount != 1 {
		t.Fatalf("unexpected pcapng quality: %+v", quality)
	}
	if quality.Interfaces[0].LinkType != layers.LinkTypeEthernet.String() {
		t.Fatalf("unexpected link type: %+v", quality.Interfaces[0])
	}
}

// Non-Ethernet captures are valid inputs but cannot support Ethernet control
// plane conclusions. This is a capture limitation, not evidence of a loop.
func TestInspectCaptureNonEthernetIsDegraded(t *testing.T) {
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeIPv4); err != nil {
		t.Fatal(err)
	}
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Unix(1000, 0), CaptureLength: len(ipv4), Length: len(ipv4),
	}, ipv4); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "raw-ip.pcap")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "degraded" || len(result.Capabilities) != 0 {
		t.Fatalf("non-Ethernet capture was treated as Ethernet-capable: %+v", result)
	}
	found := false
	for _, issue := range result.Limitations {
		if issue.Code == "ethernet_not_observable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing capture limitation: %+v", result.Limitations)
	}
}

// A truncated pcapng must not silently be interpreted as an empty or healthy
// capture. Unlike a missing packet, a malformed block cannot be trusted.
func TestInspectCaptureRejectsTruncatedPCAPNG(t *testing.T) {
	path, data := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(100, 0), CaptureLength: 60, Length: 60,
	}})
	if len(data) < 16 {
		t.Fatalf("bad synthetic pcapng fixture length: %d", len(data))
	}
	if err := os.WriteFile(path, data[:len(data)-9], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil {
		t.Fatal("truncated pcapng unexpectedly accepted")
	}
}

func TestInspectCaptureRetainsPCAPNGSections(t *testing.T) {
	var buf bytes.Buffer
	t0 := time.Unix(1000, 0).UTC()
	packet := make([]byte, 60)
	for section, name := range []string{"first-site", "second-site"} {
		writer, err := pcapgo.NewNgWriterInterface(&buf, pcapgo.NgInterface{
			Name: name, LinkType: layers.LinkTypeEthernet,
		}, pcapgo.DefaultNgWriterOptions)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < section+1; i++ {
			ci := gopacket.CaptureInfo{
				Timestamp:     t0.Add(time.Duration(section*10+i) * time.Second),
				CaptureLength: len(packet), Length: len(packet),
			}
			if err := writer.WritePacket(ci, packet); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "two-sections.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.PacketCount != 3 || len(result.Interfaces) != 2 {
		t.Fatalf("lost interface metadata across sections: %+v", result)
	}
	if result.Interfaces[0].SectionIndex != 0 || result.Interfaces[0].Name != "first-site" ||
		result.Interfaces[0].PacketCount != 1 {
		t.Errorf("first section misattributed: %+v", result.Interfaces[0])
	}
	if result.Interfaces[1].SectionIndex != 1 || result.Interfaces[1].Name != "second-site" ||
		result.Interfaces[1].PacketCount != 2 {
		t.Errorf("second section misattributed: %+v", result.Interfaces[1])
	}
}

func TestInspectCaptureHonorsPCAPNGCaptureFilter(t *testing.T) {
	var buf bytes.Buffer
	writer, err := pcapgo.NewNgWriterInterface(&buf, pcapgo.NgInterface{
		Name: "filtered-uplink", LinkType: layers.LinkTypeEthernet,
		Filter: "tcp port 443",
	}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 60)
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Unix(1000, 0), CaptureLength: len(p), Length: len(p),
	}, p); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "filtered.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := InspectCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Interfaces) != 1 || result.Interfaces[0].Filter != "tcp port 443" {
		t.Fatalf("capture filter lost: %+v", result.Interfaces)
	}
	if result.Status != "degraded" {
		t.Errorf("filtered capture marked good: %+v", result)
	}
	for _, cap := range result.Capabilities {
		if cap == "stp_bpdu" || cap == "lacp_slow_protocols" {
			t.Errorf("asserted control-plane visibility with a capture filter: %q", cap)
		}
	}
	found := false
	for _, issue := range result.Limitations {
		if issue.Code == "interface_capture_filter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing filter limitation: %+v", result.Limitations)
	}
}

func TestPreflightAndAnalysisShareDescriptorAndDetectModification(t *testing.T) {
	t0 := time.Unix(1000, 0).UTC()
	path, _ := makeQualityFixture(t, false, []gopacket.CaptureInfo{{
		Timestamp: t0, CaptureLength: 60, Length: 60,
	}})
	quality, handle, err := InspectCaptureAndOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	// Atomic path replacement must not switch the bytes consumed by the
	// analyzer: the handle is bound to the original opened inode.
	moved := path + ".original"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("different file at the original name"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := handle.Reader.ReadPacketData(); err != nil {
		t.Fatalf("reader incorrectly followed replacement path: %v", err)
	}
	if err := VerifyCaptureHandle(handle, quality); err != nil {
		t.Fatalf("same opened inode unexpectedly changed: %v", err)
	}
	// Replacing the contents of that inode must invalidate the analysis.
	if err := os.WriteFile(moved, []byte("modified in place"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCaptureHandle(handle, quality); err == nil {
		t.Fatal("accepted a capture whose opened descriptor changed after preflight")
	}
}
