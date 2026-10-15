package analyzer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// PCAPNG may carry large metadata blocks, but any *single packet* larger than
// this bound is outside TraceSleuth's supported packet-capture resource model.
// It prevents a corrupt capture-length field from allocating gigabytes in
// the pinned third-party NgReader, before the parser can return an error.
const maxPCAPNGPacketBytes uint64 = 16 << 20

// validatePCAPNGBlockFraming checks all on-disk block envelopes and the
// declared lengths of packet-bearing blocks before gopacket receives a file.
// gopacket/pcapgo v1.1.19 can return a normal io.EOF in the middle of a block.
// The scan uses bounded ReaderAt calls on the same descriptor, in O(1)
// auxiliary memory, and returns the validated file extent for bounded reads.
// Packet protocol semantics remain the decoder's responsibility.
func validatePCAPNGBlockFraming(file *os.File) (int64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat PCAPNG capture: %w", err)
	}
	size := info.Size()
	if size < 28 {
		return 0, fmt.Errorf("truncated PCAPNG section header")
	}

	sectionMagic := []byte{0x0a, 0x0d, 0x0d, 0x0a}
	var header [12]byte
	var fixedPacketHeader [28]byte
	var trailer [4]byte
	var order binary.ByteOrder

	for offset := int64(0); offset < size; {
		if size-offset < int64(len(header)) {
			return 0, fmt.Errorf("truncated PCAPNG block header at byte %d", offset)
		}
		if _, err := file.ReadAt(header[:], offset); err != nil {
			return 0, fmt.Errorf("read PCAPNG block header at byte %d: %w", offset, err)
		}
		isSection := bytes.Equal(header[:4], sectionMagic)
		if isSection {
			switch {
			case bytes.Equal(header[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}):
				order = binary.LittleEndian
			case bytes.Equal(header[8:12], []byte{0x1a, 0x2b, 0x3c, 0x4d}):
				order = binary.BigEndian
			default:
				return 0, fmt.Errorf("invalid PCAPNG byte-order magic at byte %d", offset)
			}
		} else if order == nil {
			return 0, fmt.Errorf("PCAPNG starts without a section header at byte %d", offset)
		}

		blockType := order.Uint32(header[:4])
		blockLength := order.Uint32(header[4:8])
		minimum := uint32(12)
		switch blockType {
		case 0x0a0d0d0a: // Section Header Block
			minimum = 28
		case 1: // Interface Description Block
			minimum = 20
		case 2, 6: // Packet Block (legacy) / Enhanced Packet Block
			minimum = 32
		case 3: // Simple Packet Block
			minimum = 16
		case 4: // Name Resolution Block
			minimum = 16
		case 5: // Interface Statistics Block
			minimum = 24
		case 10: // Decryption Secrets Block
			minimum = 20
		case 0x00000bad, 0x40000bad: // Custom blocks contain a private enterprise number
			minimum = 16
		}
		if blockLength < minimum || blockLength%4 != 0 {
			return 0, fmt.Errorf("invalid PCAPNG block type %d length %d at byte %d", blockType, blockLength, offset)
		}
		if int64(blockLength) > size-offset {
			return 0, fmt.Errorf("truncated PCAPNG block at byte %d: need %d bytes, have %d", offset, blockLength, size-offset)
		}

		switch blockType {
		case 2, 6:
			// Both legacy PB and enhanced EPB have the captured and original
			// byte lengths at block-relative offsets 20 and 24, respectively.
			// Require all padded packet bytes to fit before the final trailer.
			if _, err := file.ReadAt(fixedPacketHeader[:], offset); err != nil {
				return 0, fmt.Errorf("read PCAPNG packet header at byte %d: %w", offset, err)
			}
			captured := uint64(order.Uint32(fixedPacketHeader[20:24]))
			original := uint64(order.Uint32(fixedPacketHeader[24:28]))
			padded := (captured + 3) &^ uint64(3)
			if captured > maxPCAPNGPacketBytes || captured > original ||
				uint64(blockLength) < 32+padded {
				return 0, fmt.Errorf("invalid PCAPNG packet length at byte %d: captured=%d original=%d block=%d", offset, captured, original, blockLength)
			}
		case 3:
			// The SPB has an implicit capture length derived from its block
			// extent. Bound it too, to prevent huge allocations on read.
			if uint64(blockLength)-16 > maxPCAPNGPacketBytes+3 {
				return 0, fmt.Errorf("oversize PCAPNG simple packet at byte %d", offset)
			}
		}

		if _, err := file.ReadAt(trailer[:], offset+int64(blockLength)-4); err != nil {
			return 0, fmt.Errorf("read PCAPNG block trailer at byte %d: %w", offset, err)
		}
		if order.Uint32(trailer[:]) != blockLength {
			return 0, fmt.Errorf("PCAPNG block trailer mismatch at byte %d", offset)
		}
		offset += int64(blockLength)
	}
	return size, nil
}
