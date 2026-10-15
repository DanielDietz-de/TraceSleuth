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

func framedPCAPNGBlock(typ uint32, body []byte) []byte {
	var out bytes.Buffer
	length := uint32(len(body) + 12)
	_ = binary.Write(&out, binary.LittleEndian, typ)
	_ = binary.Write(&out, binary.LittleEndian, length)
	out.Write(body)
	_ = binary.Write(&out, binary.LittleEndian, length)
	return out.Bytes()
}

func TestPCAPNGFramingRejectsUnsafeMetadataAndSimplePacket(t *testing.T) {
	validPath, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	// Format: an 8-byte IDB fixed body with a 4-byte malformed option.
	// A filter option with zero bytes would panic in the pinned NgReader
	// because it accesses optionValue[1:] unconditionally.
	shortFilterBody := make([]byte, 12)
	binary.LittleEndian.PutUint16(shortFilterBody[8:10], 11)
	// An option claiming four bytes when none remain would read into the
	// trailing block-length word and report plain EOF after good traffic.
	overflowOptionBody := append([]byte(nil), shortFilterBody...)
	binary.LittleEndian.PutUint16(overflowOptionBody[8:10], 2)
	binary.LittleEndian.PutUint16(overflowOptionBody[10:12], 4)

	shortStatisticsBody := make([]byte, 16)
	binary.LittleEndian.PutUint16(shortStatisticsBody[12:14], 5)
	binary.LittleEndian.PutUint16(shortStatisticsBody[14:16], 0)

	// A Simple Packet Block declares 60 original bytes but contains no
	// captured bytes. With snaplen=0 (unlimited) the pinned parser would
	// attempt to read missing bytes and incorrectly accept a clean prefix.
	shortSimpleBody := make([]byte, 4)
	binary.LittleEndian.PutUint32(shortSimpleBody, 60)
	hugeSimpleBody := make([]byte, 4)
	binary.LittleEndian.PutUint32(hugeSimpleBody, ^uint32(0))

	for _, tc := range []struct {
		name  string
		block []byte
	}{
		{"zero-length filter", framedPCAPNGBlock(1, shortFilterBody)},
		{"option consuming trailer", framedPCAPNGBlock(1, overflowOptionBody)},
		{"zero-length ISB count", framedPCAPNGBlock(5, shortStatisticsBody)},
		{"missing simple packet bytes", framedPCAPNGBlock(3, shortSimpleBody)},
		{"huge simple packet length", framedPCAPNGBlock(3, hugeSimpleBody)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(validPath, append(append([]byte(nil), valid...), tc.block...), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := InspectCapture(validPath)
			if err == nil {
				t.Fatalf("%s accepted by capture preflight", tc.name)
			}
			if _, err := NewComparator(false).Compare(validPath, validPath); err == nil {
				t.Fatalf("%s accepted by comparator", tc.name)
			}
		})
	}
}

func TestPCAPNGFramingAcceptsCompleteSimplePacket(t *testing.T) {
	var buf bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 60)
	packet[12], packet[13] = 0x08, 0x00
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Unix(100, 0), CaptureLength: 60, Length: 60,
	}, packet); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	// The writer emits a valid SHB+IDB+EPB; append a valid SPB with
	// original length 60 and the matching padded 60-byte payload.
	simple := make([]byte, 64)
	binary.LittleEndian.PutUint32(simple[:4], 60)
	copy(simple[4:], packet)
	data := append(buf.Bytes(), framedPCAPNGBlock(3, simple)...)
	path := filepath.Join(t.TempDir(), "complete.pcapng")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	size, err := validatePCAPNGBlockFraming(f)
	if err != nil || size != int64(len(data)) {
		t.Fatalf("valid simple packet framing rejected: size %d, error %v", size, err)
	}
	if _, err := InspectCapture(path); err != nil {
		t.Fatalf("valid SPB rejected by higher-level preflight: %v", err)
	}
}
