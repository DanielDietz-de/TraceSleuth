package analyzer

import (
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
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
