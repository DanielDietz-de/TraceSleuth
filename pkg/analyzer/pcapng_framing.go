package analyzer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// validatePCAPNGBlockFraming checks the entire on-disk block envelope before
// any packet is analyzed. gopacket/pcapgo v1.1.19 can return a plain io.EOF
// for a partially read PCAPNG block, indistinguishable from a clean EOF.
// A bounded ReaderAt scan prevents malformed tails being misdiagnosed as
// missing packets by both the single-capture and comparator paths.
//
// This verifies framing, NOT packet semantics; the normal decoder still
// validates packet-level content. It uses constant memory and the descriptor
// already opened for analysis, so pathname replacements do not alter the scan.
func validatePCAPNGBlockFraming(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat PCAPNG capture: %w", err)
	}
	size := info.Size()
	if size < 28 {
		return fmt.Errorf("truncated PCAPNG section header")
	}

	sectionMagic := []byte{0x0a, 0x0d, 0x0d, 0x0a}
	var header [12]byte
	var trailer [4]byte
	var order binary.ByteOrder

	for offset := int64(0); offset < size; {
		if size-offset < int64(len(header)) {
			return fmt.Errorf("truncated PCAPNG block header at byte %d", offset)
		}
		if _, err := file.ReadAt(header[:], offset); err != nil {
			return fmt.Errorf("read PCAPNG block header at byte %d: %w", offset, err)
		}
		isSection := bytes.Equal(header[:4], sectionMagic)
		if isSection {
			switch {
			case bytes.Equal(header[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}):
				order = binary.LittleEndian
			case bytes.Equal(header[8:12], []byte{0x1a, 0x2b, 0x3c, 0x4d}):
				order = binary.BigEndian
			default:
				return fmt.Errorf("invalid PCAPNG byte-order magic at byte %d", offset)
			}
		} else if order == nil {
			return fmt.Errorf("PCAPNG starts without a section header at byte %d", offset)
		}

		blockLength := order.Uint32(header[4:8])
		minimum := uint32(12)
		if isSection {
			minimum = 28
		}
		if blockLength < minimum || blockLength%4 != 0 {
			return fmt.Errorf("invalid PCAPNG block length %d at byte %d", blockLength, offset)
		}
		if int64(blockLength) > size-offset {
			return fmt.Errorf("truncated PCAPNG block at byte %d: need %d bytes, have %d", offset, blockLength, size-offset)
		}
		if _, err := file.ReadAt(trailer[:], offset+int64(blockLength)-4); err != nil {
			return fmt.Errorf("read PCAPNG block trailer at byte %d: %w", offset, err)
		}
		if order.Uint32(trailer[:]) != blockLength {
			return fmt.Errorf("PCAPNG block trailer mismatch at byte %d", offset)
		}
		offset += int64(blockLength)
	}
	return nil
}
