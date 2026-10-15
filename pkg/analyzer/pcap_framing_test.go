package analyzer

import (
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
)

func TestClassicPCAPFramingRejectsUnsafeCaptureLength(t *testing.T) {
	path, clean := makeQualityFixture(t, false, []gopacket.CaptureInfo{{
		Timestamp: time.Unix(1234, 0), CaptureLength: 60, Length: 60,
	}})
	for _, tc := range []struct {
		name       string
		captureLen uint32
		wireLen    uint32
		extraBytes int
	}{
		{"huge declared length", ^uint32(0), ^uint32(0), 0},
		{"missing packet contents", 54, 54, 0},
		{"caplen greater than original", 64, 60, 64},
		{"caplen exceeds snaplen", 65536, 65536, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := append([]byte(nil), clean...)
			record := make([]byte, 16)
			binary.LittleEndian.PutUint32(record[8:12], tc.captureLen)
			binary.LittleEndian.PutUint32(record[12:16], tc.wireLen)
			broken = append(broken, record...)
			broken = append(broken, make([]byte, tc.extraBytes)...)
			if err := os.WriteFile(path, broken, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectCapture(path); err == nil {
				t.Fatalf("invalid classic PCAP accepted: %s", tc.name)
			}
			if _, err := NewComparator(false).Compare(path, path); err == nil {
				t.Fatalf("invalid classic PCAP comparison accepted: %s", tc.name)
			}
		})
	}
}

func TestClassicPCAPFramingAcceptsBothEndianFormats(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
		magic uint32
	}{
		{"little", binary.LittleEndian, pcapMagicBE},
		{"big", binary.BigEndian, pcapMagicBE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make([]byte, 24)
			tc.order.PutUint32(header[:4], tc.magic)
			tc.order.PutUint16(header[4:6], 2)
			tc.order.PutUint16(header[6:8], 4)
			tc.order.PutUint32(header[16:20], 65535)
			tc.order.PutUint32(header[20:24], 1)
			record := make([]byte, 16+60)
			tc.order.PutUint32(record[0:4], 1234)
			tc.order.PutUint32(record[8:12], 60)
			tc.order.PutUint32(record[12:16], 60)
			path := t.TempDir() + "/capture.pcap"
			if err := os.WriteFile(path, append(header, record...), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectCapture(path); err != nil {
				t.Fatalf("valid %s-endian PCAP rejected: %v", tc.name, err)
			}
		})
	}
}
