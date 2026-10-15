package analyzer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// The pinned pcapgo NgReader allocates CaptureLength before reading packet
// bytes. Enforce a finite per-packet bound on untrusted PCAPNG input.
const maxPCAPNGPacketBytes uint64 = 16 << 20

// Hard bounds for serialized per-interface metadata. A capture with millions
// of tiny section/IDB blocks must not expand into unbounded JSON and heap
// allocations. This is explicitly a pre-production limit, not silent sampling.
const (
	maxPCAPNGSections                   = 1024
	maxPCAPNGInterfaces                 = 8192
	maxPCAPNGPerSectionIDs              = 256
	maxPCAPNGIDBOptionBytes             = 2048
	maxPCAPNGIDBMetadataBytes           = 1 << 20
	maxPCAPNGTrailingOptionPaddingBytes = 4 << 10
	// Limit metadata complexity, not just file bytes. A small upload can
	// otherwise contain millions of tiny unknown blocks/options and force
	// one syscall and one decoder iteration per record.
	maxPCAPNGAllOptionBytes  = 2 << 20
	maxPCAPNGOptionEntries   = 32 << 10
	maxPCAPNGNonPacketBlocks = 32 << 10
)

type pcapngOptionBudget struct {
	totalBytes       uint64
	entries          uint64
	idbMetadataBytes uint64
}

// validatePCAPNGOptions validates metadata TLVs *within* their containing
// block. The pinned NgReader does not reliably distinguish truncated option
// values from clean EOF and indexes some options without a length check.
func validatePCAPNGOptions(file *os.File, start, end int64, order binary.ByteOrder, blockType uint32, budget *pcapngOptionBudget) error {
	if end < start || uint64(end-start) > maxPCAPNGAllOptionBytes-budget.totalBytes {
		return fmt.Errorf("capture exceeds %d-byte PCAPNG option budget", maxPCAPNGAllOptionBytes)
	}
	budget.totalBytes += uint64(end - start)
	var optionHeader [4]byte
	for pos := start; pos < end; {
		if end-pos < 4 {
			return fmt.Errorf("partial PCAPNG option header at byte %d", pos)
		}
		if _, err := file.ReadAt(optionHeader[:], pos); err != nil {
			return fmt.Errorf("read PCAPNG option at byte %d: %w", pos, err)
		}
		budget.entries++
		if budget.entries > maxPCAPNGOptionEntries {
			return fmt.Errorf("capture exceeds %d PCAPNG option entries", maxPCAPNGOptionEntries)
		}
		code := order.Uint16(optionHeader[:2])
		length := uint64(order.Uint16(optionHeader[2:]))
		if code == 0 {
			if length != 0 {
				return fmt.Errorf("invalid PCAPNG end-of-options length at byte %d", pos)
			}
			// Some captures legitimately pad an option area after its end
			// marker. Bound both the accepted excess and the number of syscalls;
			// otherwise a single large zero-filled block can induce hundreds of
			// millions of four-byte ReadAt calls in preflight.
			remaining := end - (pos + 4)
			if remaining > maxPCAPNGTrailingOptionPaddingBytes {
				return fmt.Errorf("PCAPNG option padding at byte %d exceeds %d bytes", pos, maxPCAPNGTrailingOptionPaddingBytes)
			}
			var chunk [4096]byte
			for tail := pos + 4; tail < end; {
				n := len(chunk)
				if int64(n) > end-tail {
					n = int(end - tail)
				}
				if _, err := file.ReadAt(chunk[:n], tail); err != nil {
					return fmt.Errorf("read PCAPNG option padding: %w", err)
				}
				for i, b := range chunk[:n] {
					if b != 0 {
						return fmt.Errorf("non-zero bytes after PCAPNG end-of-options at byte %d", tail+int64(i))
					}
				}
				tail += int64(n)
			}
			return nil
		}
		// gopacket v1.1.19 reuses its prior option-value buffer for empty
		// options. An empty recognized field (e.g. if_name) can therefore
		// retain a large, unrelated previous option. Reject all zero-length
		// non-terminator options before decoder allocation and JSON output.
		if length == 0 {
			return fmt.Errorf("unsafe zero-length PCAPNG option %d at byte %d", code, pos)
		}
		padded := (length + 3) &^ uint64(3)
		if padded > uint64(end-pos-4) {
			return fmt.Errorf("PCAPNG option at byte %d exceeds block boundary", pos)
		}
		// IDB strings and filters are retained by NgReader and serialized in
		// JSON. Bound each option and the cumulative capture metadata before
		// decoder allocation or JSON escaping can amplify untrusted strings.
		if blockType == 1 {
			if length > maxPCAPNGIDBOptionBytes {
				return fmt.Errorf("PCAPNG interface option at byte %d exceeds %d-byte metadata field limit", pos, maxPCAPNGIDBOptionBytes)
			}
			if budget.idbMetadataBytes+length > maxPCAPNGIDBMetadataBytes {
				return fmt.Errorf("capture exceeds %d-byte PCAPNG interface metadata budget", maxPCAPNGIDBMetadataBytes)
			}
			budget.idbMetadataBytes += length
		}
		// Only validate known options *interpreted* by the pinned reader.
		// Other legal TLVs are opaque but must respect their envelope.
		minLength := uint64(0)
		switch blockType {
		case 1: // Interface Description Block
			switch code {
			case 9, 11: // timestamp resolution / filter type byte
				minLength = 1
			case 14: // timestamp offset
				minLength = 8
			}
		case 5: // Interface Statistics Block
			if code >= 2 && code <= 5 { // timestamps and counts
				minLength = 8
			}
		}
		if length < minLength {
			return fmt.Errorf("PCAPNG option %d in block %d is too short at byte %d", code, blockType, pos)
		}
		if blockType == 1 && code == 9 {
			// The pinned gopacket NgReader computes 2^exponent or
			// 10^exponent in uint64; values beyond the representable range
			// wrap its time denominator to zero and panic on division.
			var encoded [1]byte
			if _, err := file.ReadAt(encoded[:], pos+4); err != nil {
				return fmt.Errorf("read PCAPNG timestamp resolution: %w", err)
			}
			exponent := encoded[0] & 0x7f
			if (encoded[0]&0x80 != 0 && exponent > 9) ||
				(encoded[0]&0x80 == 0 && exponent > 19) {
				return fmt.Errorf("PCAPNG timestamp resolution exceeds safe uint64 precision at byte %d", pos)
			}
		}
		pos += 4 + int64(padded)
	}
	return nil
}

// validatePCAPNGBlockFraming verifies all known packet/metadata block framing
// before any third-party decoder sees untrusted input. The check is bounded in
// memory (ReaderAt, no block allocation), supports multiple byte orders and
// returns the validated extent for an io.SectionReader snapshot.
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
	var snaplens []uint32
	sections := 0
	interfaces := 0
	var optionBudget pcapngOptionBudget
	var nonPacketBlocks uint64
	// The section-length field counts bytes after the Section Header Block.
	// -1 in the on-wire signed value signifies unknown section length.
	expectedSectionEnd := int64(-1)

	for offset := int64(0); offset < size; {
		if size-offset < int64(len(header)) {
			return 0, fmt.Errorf("truncated PCAPNG block header at byte %d", offset)
		}
		if _, err := file.ReadAt(header[:], offset); err != nil {
			return 0, fmt.Errorf("read PCAPNG block header at byte %d: %w", offset, err)
		}
		isSection := bytes.Equal(header[:4], sectionMagic)
		if isSection {
			if expectedSectionEnd >= 0 && offset != expectedSectionEnd {
				return 0, fmt.Errorf("PCAPNG section ends at byte %d, but next section begins at %d", expectedSectionEnd, offset)
			}
			sections++
			if sections > maxPCAPNGSections {
				return 0, fmt.Errorf("capture has more than %d PCAPNG sections", maxPCAPNGSections)
			}
			switch {
			case bytes.Equal(header[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a}):
				order = binary.LittleEndian
			case bytes.Equal(header[8:12], []byte{0x1a, 0x2b, 0x3c, 0x4d}):
				order = binary.BigEndian
			default:
				return 0, fmt.Errorf("invalid PCAPNG byte-order magic at byte %d", offset)
			}
			snaplens = nil // interface IDs restart in every section
		} else if order == nil {
			return 0, fmt.Errorf("PCAPNG starts without a section header at byte %d", offset)
		} else if expectedSectionEnd >= 0 && offset >= expectedSectionEnd {
			return 0, fmt.Errorf("PCAPNG block at byte %d occurs past declared section end %d", offset, expectedSectionEnd)
		}

		blockType := order.Uint32(header[:4])
		blockLength := order.Uint32(header[4:8])
		// Normal traffic may contain many packet blocks. However, unbounded
		// tiny metadata and unknown blocks permit record-amplification DoS.
		if blockType != 2 && blockType != 3 && blockType != 6 {
			nonPacketBlocks++
			if nonPacketBlocks > maxPCAPNGNonPacketBlocks {
				return 0, fmt.Errorf("capture exceeds %d PCAPNG non-packet blocks", maxPCAPNGNonPacketBlocks)
			}
		}
		minimum := uint32(12)
		switch blockType {
		case 0x0a0d0d0a:
			minimum = 28
		case 1: // Interface Description
			minimum = 20
		case 2, 6: // Obsolete Packet / Enhanced Packet
			minimum = 32
		case 3: // Simple Packet
			minimum = 16
		case 4: // Name Resolution
			minimum = 16
		case 5: // Interface Statistics
			minimum = 24
		case 10: // Decryption Secrets
			minimum = 20
		case 0x00000bad, 0x40000bad: // Custom blocks
			minimum = 16
		}
		if blockLength < minimum || blockLength%4 != 0 {
			return 0, fmt.Errorf("invalid PCAPNG block type %d length %d at byte %d", blockType, blockLength, offset)
		}
		if int64(blockLength) > size-offset {
			return 0, fmt.Errorf("truncated PCAPNG block at byte %d: need %d bytes, have %d", offset, blockLength, size-offset)
		}
		if !isSection && expectedSectionEnd >= 0 && int64(blockLength) > expectedSectionEnd-offset {
			return 0, fmt.Errorf("PCAPNG block at byte %d crosses declared section end %d", offset, expectedSectionEnd)
		}

		switch blockType {
		case 0x0a0d0d0a: // Section header: 24-byte fixed data, then options
			var lengthBytes [8]byte
			if _, err := file.ReadAt(lengthBytes[:], offset+16); err != nil {
				return 0, fmt.Errorf("read PCAPNG section length at byte %d: %w", offset, err)
			}
			declaredLength := order.Uint64(lengthBytes[:])
			if declaredLength == ^uint64(0) {
				expectedSectionEnd = -1
			} else {
				available := uint64(size - offset - int64(blockLength))
				if declaredLength > available {
					return 0, fmt.Errorf("PCAPNG section at byte %d declares %d bytes but only %d remain", offset, declaredLength, available)
				}
				expectedSectionEnd = offset + int64(blockLength) + int64(declaredLength)
			}
			if err := validatePCAPNGOptions(file, offset+24, offset+int64(blockLength)-4, order, blockType, &optionBudget); err != nil {
				return 0, err
			}
		case 1: // Interface descriptor: 8-byte fixed data
			interfaces++
			if interfaces > maxPCAPNGInterfaces || len(snaplens) >= maxPCAPNGPerSectionIDs {
				return 0, fmt.Errorf("capture exceeds PCAPNG interface metadata limit")
			}
			var desc [8]byte
			if _, err := file.ReadAt(desc[:], offset+8); err != nil {
				return 0, fmt.Errorf("read interface descriptor: %w", err)
			}
			snaplens = append(snaplens, order.Uint32(desc[4:8]))
			if err := validatePCAPNGOptions(file, offset+16, offset+int64(blockLength)-4, order, blockType, &optionBudget); err != nil {
				return 0, err
			}
		case 5: // Interface statistics: 12-byte fixed data
			if err := validatePCAPNGOptions(file, offset+20, offset+int64(blockLength)-4, order, blockType, &optionBudget); err != nil {
				return 0, err
			}
		case 2, 6:
			if _, err := file.ReadAt(fixedPacketHeader[:], offset); err != nil {
				return 0, fmt.Errorf("read PCAPNG packet header at byte %d: %w", offset, err)
			}
			captured := uint64(order.Uint32(fixedPacketHeader[20:24]))
			original := uint64(order.Uint32(fixedPacketHeader[24:28]))
			padded := (captured + 3) &^ uint64(3)
			// The obsolete Packet Block uses a uint16 interface number,
			// while the Enhanced Packet Block uses uint32 at the same offset.
			var interfaceID uint32
			if blockType == 2 {
				interfaceID = uint32(order.Uint16(fixedPacketHeader[8:10]))
			} else {
				interfaceID = order.Uint32(fixedPacketHeader[8:12])
			}
			if uint64(interfaceID) >= uint64(len(snaplens)) {
				return 0, fmt.Errorf("PCAPNG packet references unknown interface at byte %d", offset)
			}
			if snap := snaplens[interfaceID]; snap != 0 && captured > uint64(snap) {
				return 0, fmt.Errorf("PCAPNG captured packet exceeds interface snaplen at byte %d", offset)
			}
			if captured == 0 || captured > maxPCAPNGPacketBytes || captured > original ||
				uint64(blockLength) < 32+padded {
				return 0, fmt.Errorf("invalid PCAPNG packet length at byte %d: captured=%d original=%d block=%d", offset, captured, original, blockLength)
			}
		case 3:
			// SPB has no explicit captured length: read min(original,
			// interface-zero snaplen), and ensure the padded bytes exist.
			if len(snaplens) == 0 {
				return 0, fmt.Errorf("PCAPNG simple packet precedes interface descriptor at byte %d", offset)
			}
			var field [4]byte
			if _, err := file.ReadAt(field[:], offset+8); err != nil {
				return 0, fmt.Errorf("read PCAPNG simple packet size: %w", err)
			}
			captured := uint64(order.Uint32(field[:]))
			if snaplens[0] != 0 && captured > uint64(snaplens[0]) {
				captured = uint64(snaplens[0])
			}
			padded := (captured + 3) &^ uint64(3)
			if captured == 0 || captured > maxPCAPNGPacketBytes || uint64(blockLength) != 16+padded {
				return 0, fmt.Errorf("invalid PCAPNG simple packet size at byte %d", offset)
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
	if expectedSectionEnd >= 0 && expectedSectionEnd != size {
		return 0, fmt.Errorf("PCAPNG ends at byte %d but section declares end at %d", size, expectedSectionEnd)
	}
	return size, nil
}
