package analyzer

import (
	"encoding/binary"
	"fmt"
	"os"
)

// A malformed classic-PCAP record can advertise multi-gigabyte caplen values.
// Validate the record envelope before pcapgo allocates its packet buffer.
// The scan uses only a fixed 24-byte/16-byte stack buffer and ReaderAt.
func validateClassicPCAPFraming(file *os.File) (int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat PCAP capture: %w", err)
	}
	size := info.Size()
	if size < 24 {
		return 0, fmt.Errorf("truncated classic PCAP global header")
	}
	var header [24]byte
	if _, err := file.ReadAt(header[:], 0); err != nil {
		return 0, fmt.Errorf("read classic PCAP header: %w", err)
	}
	magic := binary.BigEndian.Uint32(header[:4])
	var order binary.ByteOrder
	switch magic {
	case pcapMagicBE, pcapMagicNS:
		order = binary.BigEndian
	case pcapMagicLE, pcapMagicNL:
		order = binary.LittleEndian
	default:
		return 0, fmt.Errorf("invalid classic PCAP magic 0x%08x", magic)
	}
	snaplen := uint64(order.Uint32(header[16:20]))
	var record [16]byte
	packetIndex := 0
	for offset := int64(24); offset < size; {
		if size-offset < int64(len(record)) {
			return 0, &MalformedCaptureRecordError{Index: packetIndex, Cause: fmt.Errorf("truncated classic PCAP packet header at byte %d", offset)}
		}
		if _, err := file.ReadAt(record[:], offset); err != nil {
			return 0, &MalformedCaptureRecordError{Index: packetIndex, Cause: fmt.Errorf("read PCAP record at byte %d: %w", offset, err)}
		}
		captured := uint64(order.Uint32(record[8:12]))
		original := uint64(order.Uint32(record[12:16]))
		if captured > maxPCAPNGPacketBytes || captured > original ||
			(snaplen != 0 && captured > snaplen) ||
			captured > uint64(size-offset-16) {
			return 0, &MalformedCaptureRecordError{Index: packetIndex, Cause: fmt.Errorf("invalid classic PCAP capture length at byte %d: captured=%d original=%d", offset, captured, original)}
		}
		offset += 16 + int64(captured)
		packetIndex++
	}
	return size, nil
}
