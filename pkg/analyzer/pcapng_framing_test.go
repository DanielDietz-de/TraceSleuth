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

func TestPCAPNGFramingHonorsFiniteSectionLengths(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	shbSize := binary.LittleEndian.Uint32(valid[4:8])
	if shbSize < 28 || int(shbSize) >= len(valid) {
		t.Fatalf("invalid fixture SHB size: %d", shbSize)
	}
	actual := uint64(len(valid) - int(shbSize))
	for _, tc := range []struct {
		name     string
		declared uint64
		valid    bool
	}{
		{"exact boundary", actual, true},
		{"shorter than block data", actual - 1, false},
		{"past file end", actual + 1, false},
		{"empty section with blocks", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint64(data[16:24], tc.declared)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := InspectCapture(path)
			if tc.valid && err != nil {
				t.Fatalf("valid finite section was rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("PCAPNG ignored a mismatched finite section length")
			}
		})
	}
}

func TestPCAPNGFramingLimitsRetainedInterfaceOptionBytes(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	makeIDB := func(size int) []byte {
		body := make([]byte, 8+4+((size+3)&^3))
		binary.LittleEndian.PutUint16(body[0:2], 1)
		binary.LittleEndian.PutUint32(body[4:8], 65535)
		binary.LittleEndian.PutUint16(body[8:10], 2)
		binary.LittleEndian.PutUint16(body[10:12], uint16(size))
		for i := 0; i < size; i++ {
			body[12+i] = 'a'
		}
		return framedPCAPNGBlock(1, body)
	}
	oversized := append(append([]byte(nil), valid...), makeIDB(maxPCAPNGIDBOptionBytes+1)...)
	if err := os.WriteFile(path, oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "metadata field limit") {
		t.Fatalf("oversized PCAPNG IDB option accepted: %v", err)
	}

	// Several individually permitted IDB names can still exceed the total
	// capture metadata budget within the section/interface count limits.
	var shbBody [16]byte
	binary.LittleEndian.PutUint32(shbBody[:4], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(shbBody[4:6], 1)
	binary.LittleEndian.PutUint64(shbBody[8:16], ^uint64(0))
	section := framedPCAPNGBlock(0x0a0d0d0a, shbBody[:])
	idb := makeIDB(maxPCAPNGIDBOptionBytes)
	data := append([]byte(nil), valid...)
	for s := 0; s < 3; s++ {
		data = append(data, section...)
		for i := 0; i < maxPCAPNGPerSectionIDs; i++ {
			data = append(data, idb...)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "metadata budget") {
		t.Fatalf("cumulative PCAPNG IDB metadata amplification accepted: %v", err)
	}
}

// A zero-length recognized field is not safe with the pinned NgReader: it
// reuses an option buffer, allowing one large field to be retained for many
// subsequent interfaces. Reject the block before the third-party decoder.
func TestPCAPNGFramingRejectsZeroLengthRetainedOptionAfterPriorValue(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	body := make([]byte, 8+4+4+4)
	binary.LittleEndian.PutUint16(body[0:2], 1) // Ethernet
	binary.LittleEndian.PutUint32(body[4:8], 65535)
	binary.LittleEndian.PutUint16(body[8:10], 2999) // nonempty unknown option
	binary.LittleEndian.PutUint16(body[10:12], 4)
	copy(body[12:16], []byte("test"))
	binary.LittleEndian.PutUint16(body[16:18], 2) // if_name: zero length
	data := append(append([]byte(nil), valid...), framedPCAPNGBlock(1, body)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "zero-length PCAPNG option") {
		t.Fatalf("zero-length interface name was not rejected: %v", err)
	}
	if _, err := NewComparator(false).Compare(path, path); err == nil {
		t.Fatal("comparator accepted zero-length interface metadata")
	}
}

// Large runs of zeros after an option terminator must not trigger one syscall
// per four bytes. The accepted padding budget keeps preflight proportional to
// useful capture metadata and prevents CPU-based upload denial of service.
func TestPCAPNGFramingCapsTrailingOptionPadding(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	buildIDB := func(padding int) []byte {
		body := make([]byte, 8+4+padding)
		binary.LittleEndian.PutUint16(body[:2], 1)
		binary.LittleEndian.PutUint32(body[4:8], 65535)
		// The four zero bytes at [8:12] are the legal end-of-options marker.
		return framedPCAPNGBlock(1, body)
	}
	for _, tc := range []struct {
		name    string
		padding int
		valid   bool
	}{
		{"bounded zeros", maxPCAPNGTrailingOptionPaddingBytes, true},
		{"excessive zeros", maxPCAPNGTrailingOptionPaddingBytes + 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append(append([]byte(nil), valid...), buildIDB(tc.padding)...)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = validatePCAPNGBlockFraming(f)
			_ = f.Close()
			if tc.valid && err != nil {
				t.Fatalf("valid bounded option padding rejected: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "padding")) {
				t.Fatalf("excessive option padding accepted: %v", err)
			}
			if !tc.valid {
				if _, err := InspectCapture(path); err == nil {
					t.Fatal("preflight accepted excessive padding")
				}
				if _, err := NewComparator(false).Compare(path, path); err == nil {
					t.Fatal("comparator accepted excessive padding")
				}
			}
		})
	}
}

// A bounded file with tiny unknown option TLVs can otherwise induce millions
// of syscalls and repeated third-party decoder iterations without payload.
func TestPCAPNGFramingRejectsUnboundedOptionEntries(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	// Build a legal SHB carrying more than the global count budget of 4-byte
	// values. No terminator: every TLV is a real option header/value pair.
	body := make([]byte, 16+8*(maxPCAPNGOptionEntries+1))
	binary.LittleEndian.PutUint32(body[:4], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(body[4:6], 1)
	binary.LittleEndian.PutUint64(body[8:16], ^uint64(0))
	for i := 0; i < maxPCAPNGOptionEntries+1; i++ {
		pos := 16 + 8*i
		binary.LittleEndian.PutUint16(body[pos:pos+2], 2999)
		binary.LittleEndian.PutUint16(body[pos+2:pos+4], 4)
		copy(body[pos+4:pos+8], "abcd")
	}
	data := append(append([]byte(nil), valid...), framedPCAPNGBlock(0x0a0d0d0a, body)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "option entries") {
		t.Fatalf("excessive PCAPNG option records accepted: %v", err)
	}
	if _, err := NewComparator(false).Compare(path, path); err == nil {
		t.Fatal("comparison accepted a capture with unbounded option iteration")
	}
}

func TestPCAPNGFramingRejectsUnboundedUnknownBlocks(t *testing.T) {
	path, valid := makeQualityFixture(t, true, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1000, 0), CaptureLength: 60, Length: 60,
	}})
	var data bytes.Buffer
	data.Write(valid)
	block := framedPCAPNGBlock(0xfeedab00, nil)
	for i := 0; i <= maxPCAPNGNonPacketBlocks; i++ {
		data.Write(block)
	}
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(path); err == nil || !strings.Contains(err.Error(), "non-packet blocks") {
		t.Fatalf("excessive unknown PCAPNG blocks accepted: %v", err)
	}
	if _, err := NewComparator(false).Compare(path, path); err == nil {
		t.Fatal("comparison accepted a capture with unbounded non-packet blocks")
	}
}
