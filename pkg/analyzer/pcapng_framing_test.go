package analyzer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestPCAPNGFramingRejectsTimestampResolutionOverflow(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	for _, value := range []byte{0x14, 0x40, 0x8a, 0x9d, 0xc0, 0xff} {
		t.Run(fmt.Sprintf("resolution-0x%02x", value), func(t *testing.T) {
			// New IDB: 8-byte fixed header, if_tsresol option (code 9),
			// 1-byte value with 3 bytes of required padding.
			idb := make([]byte, 16)
			binary.LittleEndian.PutUint16(idb[:2], 1)
			binary.LittleEndian.PutUint32(idb[4:8], 65535)
			binary.LittleEndian.PutUint16(idb[8:10], 9)
			binary.LittleEndian.PutUint16(idb[10:12], 1)
			idb[12] = value
			if err := os.WriteFile(path, append(append([]byte(nil), valid...), framedPCAPNGBlock(1, idb)...), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectCapture(path); err == nil {
				t.Fatalf("overflowing timestamp precision 0x%02x was accepted", value)
			}
		})
	}
}

func TestPCAPNGFramingRejectsEPBExceedingInterfaceSnaplen(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	newIface := make([]byte, 8)
	binary.LittleEndian.PutUint16(newIface[0:2], 1)
	binary.LittleEndian.PutUint32(newIface[4:8], 64)
	// New interface has index 1 (default interface 0 is already present).
	packet := make([]byte, 20+100)
	binary.LittleEndian.PutUint32(packet[0:4], 1)
	binary.LittleEndian.PutUint32(packet[12:16], 100)
	binary.LittleEndian.PutUint32(packet[16:20], 100)
	data := append(append([]byte(nil), valid...), framedPCAPNGBlock(1, newIface)...)
	data = append(data, framedPCAPNGBlock(6, packet)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil {
		t.Fatal("EPB captured length exceeded its own interface snaplen")
	}
}

func TestPCAPNGFramingCapsSectionAndInterfaceMetadata(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1_000, 0), CaptureLength: 60, Length: 60,
	}})
	var sectionBody [16]byte
	binary.LittleEndian.PutUint32(sectionBody[:4], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(sectionBody[4:6], 1)
	binary.LittleEndian.PutUint64(sectionBody[8:16], ^uint64(0))
	section := framedPCAPNGBlock(0x0a0d0d0a, sectionBody[:])
	data := append([]byte(nil), valid...)
	for i := 0; i < maxPCAPNGSections; i++ {
		data = append(data, section...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "sections") {
		t.Fatalf("unbounded PCAPNG sections accepted: %v", err)
	}
	// One section with too many descriptor entries is separately capped.
	var descriptor [8]byte
	binary.LittleEndian.PutUint16(descriptor[:2], 1)
	binary.LittleEndian.PutUint32(descriptor[4:8], 65535)
	idb := framedPCAPNGBlock(1, descriptor[:])
	data = append([]byte(nil), valid...)
	for i := 0; i <= maxPCAPNGPerSectionIDs; i++ {
		data = append(data, idb...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "metadata limit") {
		t.Fatalf("unbounded PCAPNG interface entries accepted: %v", err)
	}
}
