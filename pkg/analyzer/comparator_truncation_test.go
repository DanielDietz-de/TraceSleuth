package analyzer

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// An incomplete packet record after valid traffic must fail comparison.
// Treating every read error as EOF would publish a misleading partial result.
func TestCompareStreamingRejectsTruncatedPacketRecord(t *testing.T) {
	path, clean := makeQualityFixture(t, false, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	corrupt := append([]byte(nil), clean...)
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[8:12], 60)
	binary.LittleEndian.PutUint32(record[12:16], 60)
	corrupt = append(corrupt, record...)
	corrupt = append(corrupt, make([]byte, 10)...)
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	comparator := NewComparator(false)
	if _, err := comparator.Compare(path, path); err == nil {
		t.Fatal("truncated comparison capture returned a plausible partial report")
	}
}

// Valid file headers are not evidence that a capture observed zero traffic.
// Reject comparisons with an empty PCAPNG even if the other side has packets.
func TestCompareStreamingRejectsHeaderOnlyPCAPNG(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(t.TempDir(), "header-only.pcapng")
	if err := os.WriteFile(empty, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	nonempty, _ := makeQualityFixture(t, false, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	comparator := NewComparator(false)
	for _, pair := range [][2]string{{empty, nonempty}, {nonempty, empty}} {
		if _, err := comparator.Compare(pair[0], pair[1]); err == nil {
			t.Fatalf("header-only comparison unexpectedly succeeded: %v", pair)
		}
	}
}

// The PCAPNG reader may conflate a partial block with a normal EOF after
// reading good packets. Both comparison sides must reject this unsafe prefix.
func TestCompareStreamingRejectsPartialPCAPNGTail(t *testing.T) {
	corruptPath, cleanNG := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	partialBlock := []byte{0x06, 0, 0, 0, 0x40, 0, 0, 0, 0x00, 0x00}
	if err := os.WriteFile(corruptPath, append(cleanNG, partialBlock...), 0600); err != nil {
		t.Fatal(err)
	}
	cleanPath, _ := makeQualityFixture(t, false, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	comparator := NewComparator(false)
	for _, pair := range [][2]string{{corruptPath, cleanPath}, {cleanPath, corruptPath}} {
		if _, err := comparator.Compare(pair[0], pair[1]); err == nil {
			t.Fatalf("PCAPNG with partial block yielded plausible comparison for %v", pair)
		}
	}
}

// An append between validated PCAPNG preflight and comparison EOF must never
// produce a plausible partial result. The reader is size-bounded and the
// final descriptor hash invalidates the concurrent mutation.
func TestCompareStreamingRejectsInPlaceAppend(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 60)
	frame[12], frame[13] = 0x08, 0x00
	frame[14] = 0x45 // IPv4 version, IHL
	frame[17] = 46   // IP total length
	frame[22], frame[23] = 64, 17
	copy(frame[26:30], []byte{192, 0, 2, 1})
	copy(frame[30:34], []byte{192, 0, 2, 2})
	frame[34], frame[35] = 0x1f, 0x90
	frame[36], frame[37] = 0, 53
	frame[39] = 26 // UDP header + payload length
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Unix(1_000, 0), CaptureLength: len(frame), Length: len(frame),
	}, frame); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "append-while-comparing.pcapng")
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	comparator := NewComparator(false)
	_, err = comparator.streamFile(path, func(_ *packetMeta) {
		calls++
		upload, openErr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, writeErr := upload.Write([]byte{0x06, 0, 0}); writeErr != nil {
			upload.Close()
			t.Fatal(writeErr)
		}
		if closeErr := upload.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	})
	if calls != 1 {
		t.Fatalf("expected comparator to stream one IPv4 packet, got %d", calls)
	}
	if err == nil || !strings.Contains(err.Error(), "capture changed") {
		t.Fatalf("in-place append was not rejected: %v", err)
	}
}
