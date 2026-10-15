package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
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

// Interface Statistics Blocks are optional. In their absence, an interface
// does not report zero drops; it has an unknown drop count.
func TestInspectCapturePCAPNGDropStatisticsUnknownVsReported(t *testing.T) {
	for _, test := range []struct {
		name           string
		writeStats     bool
		drops          uint64
		expectReported bool
	}{
		{name: "absent ISB", writeStats: false},
		{name: "explicit zero drops", writeStats: true, drops: 0, expectReported: true},
		{name: "explicit packet drops", writeStats: true, drops: 7, expectReported: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer, err := pcapgo.NewNgWriter(&buffer, layers.LinkTypeEthernet)
			if err != nil {
				t.Fatal(err)
			}
			frame := make([]byte, 60)
			if err := writer.WritePacket(gopacket.CaptureInfo{
				Timestamp:     time.Unix(1_000, 0),
				CaptureLength: len(frame), Length: len(frame),
			}, frame); err != nil {
				t.Fatal(err)
			}
			if test.writeStats {
				if err := writer.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{
					LastUpdate:      time.Unix(1_001, 0),
					PacketsDropped:  test.drops,
					PacketsReceived: pcapgo.NgNoValue64,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "capture.pcapng")
			if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			q, err := InspectCapture(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(q.Interfaces) != 1 {
				t.Fatalf("interfaces: %+v", q.Interfaces)
			}
			reported := q.Interfaces[0].ReportedDrops
			if (reported != nil) != test.expectReported {
				t.Fatalf("reported drops = %v; expected presence %v", reported, test.expectReported)
			}
			if reported != nil && *reported != test.drops {
				t.Fatalf("reported drops = %d, want %d", *reported, test.drops)
			}
			if test.drops > 0 && q.Status != "degraded" {
				t.Fatalf("reported drops did not degrade capture quality: %+v", q)
			}
		})
	}
}

// Link type alone cannot prove protocol visibility. The packet snapshot must
// retain enough bytes for the relevant header before a capability is claimed.
func TestInspectCaptureGatesCapabilitiesByUsableEthernetDepth(t *testing.T) {
	for _, tc := range []struct {
		name            string
		snapLen, capLen uint32
		want            []string
	}{
		{"ethernet header only", 14, 14, []string{"ethernet"}},
		{"ethernet with vlan tag", 18, 18, []string{"ethernet", "vlan"}},
		{"ethernet with stp depth", 54, 54, []string{"ethernet", "vlan", "stp_bpdu"}},
		{"ethernet with full lacp depth", 124, 124, []string{"ethernet", "vlan", "stp_bpdu", "lacp_slow_protocols"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := pcapgo.NewWriter(&buffer)
			if err := writer.WriteFileHeader(tc.snapLen, layers.LinkTypeEthernet); err != nil {
				t.Fatal(err)
			}
			frame := make([]byte, tc.capLen)
			if err := writer.WritePacket(gopacket.CaptureInfo{
				Timestamp:     time.Unix(1_234, 0),
				CaptureLength: int(tc.capLen), Length: 124,
			}, frame); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "short.pcap")
			if err := os.WriteFile(file, buffer.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			q, err := InspectCapture(file)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(q.Capabilities, tc.want) {
				t.Fatalf("capabilities %v, want %v; quality %+v", q.Capabilities, tc.want, q)
			}
			if tc.snapLen < minSTPBPDUDepth && q.Status != "degraded" {
				t.Fatalf("shallow Ethernet capture must be degraded: %+v", q)
			}
		})
	}
}

// An ordinary short Ethernet frame is not evidence of a 60-byte snaplen.
// Snaplen=65535 for classic PCAP and 0 (unlimited) in PCAPNG both permit
// control-plane headers even when the only observed frame happens to be short.
func TestInspectCaptureUntruncatedShortFrameDoesNotLimitCapabilities(t *testing.T) {
	for _, useNG := range []bool{false, true} {
		t.Run(map[bool]string{false: "pcap", true: "pcapng"}[useNG], func(t *testing.T) {
			path, _ := makeQualityFixture(t, useNG, []gopacket.CaptureInfo{{
				Timestamp: time.Unix(1234, 0), CaptureLength: 60, Length: 60,
			}})
			quality, err := InspectCapture(path)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"ethernet", "vlan", "stp_bpdu", "lacp_slow_protocols"}
			if !reflect.DeepEqual(quality.Capabilities, want) {
				t.Fatalf("short untruncated frame unexpectedly reduced capture capacity: %+v", quality)
			}
			if quality.Status != "good" {
				t.Fatalf("untruncated capture was downgraded: %+v", quality)
			}
		})
	}
}

// The PCAPNG reader may return io.EOF in the middle of a block. Verify
// framing independently even after earlier packet records were valid.
func TestInspectCaptureRejectsPartialPCAPNGTailAfterValidPacket(t *testing.T) {
	path, clean := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	cases := map[string][]byte{
		"partial header":      append(append([]byte(nil), clean...), 0x06, 0, 0, 0, 0x40, 0),
		"partial packet body": append(append([]byte(nil), clean...), 0x06, 0, 0, 0, 0x40, 0, 0, 0),
		"bad closing length":  append([]byte(nil), clean...),
	}
	// The last four bytes are the ending length of a complete PCAPNG block.
	cases["bad closing length"][len(clean)-4] ^= 1
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, input, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectCapture(path); err == nil {
				t.Fatal("malformed PCAPNG tail was accepted as clean EOF")
			}
		})
	}
}

// The pinned pcapgo.Reader.Resolution reports the classic-PCAP magic in
// reverse. Validate the actual original magic for both timestamp formats.
func TestClassicPCAPTimestampResolutionFromMagic(t *testing.T) {
	for _, tc := range []struct {
		name       string
		nanos      bool
		resolution string
	}{
		{"microsecond magic", false, "10^-6"},
		{"nanosecond magic", true, "10^-9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := pcapgo.NewWriter(&buf)
			if tc.nanos {
				writer = pcapgo.NewWriterNanos(&buf)
			}
			if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
				t.Fatal(err)
			}
			frame := make([]byte, 60)
			if err := writer.WritePacket(gopacket.CaptureInfo{
				Timestamp:     time.Unix(123, 456789123),
				CaptureLength: len(frame), Length: len(frame),
			}, frame); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "resolution.pcap")
			if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			quality, err := InspectCapture(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(quality.Interfaces) != 1 || quality.Interfaces[0].TimestampResolution != tc.resolution {
				t.Fatalf("timestamp resolution = %+v, want %q", quality.Interfaces, tc.resolution)
			}
		})
	}
}

// PCAPNG can aggregate many interfaces. One deep member must not make
// STP/LACP appear observable across another interface with a short snaplen.
func TestInspectCaptureMultipleInterfacesConservativelyGateCapabilities(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := pcapgo.NewNgWriterInterface(&buffer, pcapgo.NgInterface{
		Name: "shallow-mirror", LinkType: layers.LinkTypeEthernet, SnapLength: 14,
	}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	deepIndex, err := writer.AddInterface(pcapgo.NgInterface{
		Name: "full-capture", LinkType: layers.LinkTypeEthernet, SnapLength: 124,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		index  int
		length int
	}{
		{0, 14},
		{deepIndex, 124},
	} {
		packet := make([]byte, tc.length)
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:      time.Unix(123, int64(tc.index)*1e6),
			CaptureLength:  tc.length,
			Length:         tc.length,
			InterfaceIndex: tc.index,
		}, packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mixed-depth.pcapng")
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	quality, err := InspectCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	if quality.PacketCount != 2 || quality.Status != "degraded" {
		t.Fatalf("invalid quality summary for shallow capture: %+v", quality)
	}
	if !reflect.DeepEqual(quality.Capabilities, []string{"ethernet"}) {
		t.Fatalf("STP/LACP/VLAN granted using the other deeper interface: %v", quality.Capabilities)
	}
	foundShallow := false
	for _, issue := range quality.Limitations {
		if issue.Code == "insufficient_layer2_capture_depth" &&
			strings.Contains(issue.Description, "section 0 interface 0") {
			foundShallow = true
		}
	}
	if !foundShallow {
		t.Fatalf("missing per-interface limitation: %+v", quality.Limitations)
	}
	if len(quality.Interfaces) != 2 ||
		quality.Interfaces[0].PacketCount != 1 ||
		quality.Interfaces[1].PacketCount != 1 {
		t.Fatalf("incorrect packet counts per interface: %+v", quality.Interfaces)
	}
}

// With multiple capture points, reported packet drops must identify the
// source interface; otherwise UI users cannot locate the unreliable TAP.
func TestInspectCaptureIdentifiesInterfaceThatReportedDrops(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	affected, err := writer.AddInterface(pcapgo.NgInterface{
		Name: "tap-secondary", LinkType: layers.LinkTypeEthernet,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{0, affected} {
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Unix(1_000, 0),
			CaptureLength: 60, Length: 60, InterfaceIndex: idx,
		}, make([]byte, 60)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.WriteInterfaceStats(affected, pcapgo.NgInterfaceStatistics{
		LastUpdate: time.Unix(1_001, 0), PacketsDropped: 13,
		PacketsReceived: pcapgo.NgNoValue64,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "stats.pcapng")
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	quality, err := InspectCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, issue := range quality.Limitations {
		if issue.Code == "capture_reported_drops" {
			if strings.Contains(issue.Description, "section 0 interface 1") &&
				strings.Contains(issue.Description, "tap-secondary") && issue.Count == 13 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("did not attribute reported drops to capture interface: %+v", quality.Limitations)
	}
	if len(quality.Interfaces) != 2 || quality.Interfaces[0].ReportedDrops != nil ||
		quality.Interfaces[1].ReportedDrops == nil ||
		*quality.Interfaces[1].ReportedDrops != 13 {
		t.Fatalf("incorrect reported drop pointers: %+v", quality.Interfaces)
	}
}

// A complete block envelope is insufficient if a packet-specific header is
// too short or declares an impossible caplen. Both routes must reject the
// tail, even after valid prior packet records, without allocating caplen.
func TestInspectCaptureRejectsMalformedFramedPCAPNGPacketBlock(t *testing.T) {
	corruptPath, clean := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	cleanPath, _ := makeQualityFixture(t, false, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	shortEPB := make([]byte, 12)
	binary.LittleEndian.PutUint32(shortEPB[0:4], 6)
	binary.LittleEndian.PutUint32(shortEPB[4:8], 12)
	binary.LittleEndian.PutUint32(shortEPB[8:12], 12)

	missingPacketBytes := make([]byte, 32)
	binary.LittleEndian.PutUint32(missingPacketBytes[0:4], 6)
	binary.LittleEndian.PutUint32(missingPacketBytes[4:8], 32)
	binary.LittleEndian.PutUint32(missingPacketBytes[20:24], 4)
	binary.LittleEndian.PutUint32(missingPacketBytes[24:28], 4)
	binary.LittleEndian.PutUint32(missingPacketBytes[28:32], 32)

	oversizedPacket := make([]byte, 32)
	binary.LittleEndian.PutUint32(oversizedPacket[0:4], 6)
	binary.LittleEndian.PutUint32(oversizedPacket[4:8], 32)
	binary.LittleEndian.PutUint32(oversizedPacket[20:24], ^uint32(0))
	binary.LittleEndian.PutUint32(oversizedPacket[24:28], ^uint32(0))
	binary.LittleEndian.PutUint32(oversizedPacket[28:32], 32)

	for _, tc := range []struct {
		name string
		block []byte
	}{
		{"short enhanced packet block", shortEPB},
		{"packet bytes absent", missingPacketBytes},
		{"oversized declared packet", oversizedPacket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := append(append([]byte(nil), clean...), tc.block...)
			if err := os.WriteFile(corruptPath, input, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectCapture(corruptPath); err == nil {
				t.Fatal("malformed framed PCAPNG packet was accepted")
			}
			comparator := NewComparator(false)
			if _, err := comparator.Compare(corruptPath, cleanPath); err == nil {
				t.Fatal("malformed PCAPNG tail yielded a valid comparison")
			}
		})
	}
}

// A full jumbo frame on an interface does not undo evidence that a different
// record was only captured through its Ethernet header.
func TestInspectCaptureTruncatedDepthNotMaskedByFullSizedFrame(t *testing.T) {
	for _, useNG := range []bool{false, true} {
		t.Run(map[bool]string{false: "pcap", true: "pcapng"}[useNG], func(t *testing.T) {
			var buffer bytes.Buffer
			var write func(gopacket.CaptureInfo, []byte) error
			var flush func() error
			if useNG {
				w, err := pcapgo.NewNgWriter(&buffer, layers.LinkTypeEthernet)
				if err != nil {
					t.Fatal(err)
				}
				write, flush = w.WritePacket, w.Flush
			} else {
				w := pcapgo.NewWriter(&buffer)
				if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
					t.Fatal(err)
				}
				write = w.WritePacket
			}
			for _, ci := range []gopacket.CaptureInfo{
				{Timestamp: time.Unix(1, 0), CaptureLength: 1500, Length: 1500},
				{Timestamp: time.Unix(2, 0), CaptureLength: 14, Length: 124},
			} {
				if err := write(ci, make([]byte, ci.CaptureLength)); err != nil {
					t.Fatal(err)
				}
			}
			if flush != nil {
				if err := flush(); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "mixed.pcap")
			if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			quality, err := InspectCapture(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(quality.Capabilities, []string{"ethernet"}) {
				t.Fatalf("full-sized traffic masked shallow truncation: %+v", quality)
			}
		})
	}
}
