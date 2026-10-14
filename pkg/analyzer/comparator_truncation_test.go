package analyzer

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
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
