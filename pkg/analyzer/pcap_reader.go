package analyzer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ─── Unified PCAP/pcapng Reader ─────────────────────────────────

// CaptureFormat identifies the packet capture file format.
type CaptureFormat string

const (
	FormatPCAP   CaptureFormat = "pcap"
	FormatPCAPNG CaptureFormat = "pcapng"
)

// Magic bytes for format detection.
const (
	pcapMagicBE uint32 = 0xA1B2C3D4 // pcap big-endian
	pcapMagicLE uint32 = 0xD4C3B2A1 // pcap little-endian
	pcapMagicNS uint32 = 0xA1B23C4D // pcap nanosecond-resolution big-endian
	pcapMagicNL uint32 = 0x4D3CB2A1 // pcap nanosecond-resolution little-endian
	pcapngMagic uint32 = 0x0A0D0D0A // pcapng Section Header Block
)

// PacketReader is the minimal interface satisfied by both
// pcapgo.Reader (pcap) and pcapgo.NgReader (pcapng).
type PacketReader interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	LinkType() layers.LinkType
}

// CaptureHandle bundles the reader, detected format, and the
// underlying file so the caller can defer file.Close().
type CaptureHandle struct {
	Reader PacketReader
	Format CaptureFormat
	File   *os.File
}

// Close closes the underlying file.
func (h *CaptureHandle) Close() error {
	if h.File != nil {
		return h.File.Close()
	}
	return nil
}

// OpenCapture opens a packet capture file, auto-detects PCAP or PCAPNG,
// and returns a reader on an owned file descriptor.
func OpenCapture(filePath string) (*CaptureHandle, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open capture file: %w", err)
	}
	h, err := openCaptureOnFile(f, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		f.Close()
		return nil, err
	}
	return h, nil
}

// openCaptureOnFile resets a descriptor and recreates the packet reader.
// This is used between preflight and detection so both passes use the SAME
// open descriptor even when the original pathname is renamed/replaced.
func openCaptureOnFile(f *os.File, options pcapgo.NgReaderOptions) (*CaptureHandle, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek capture: %w", err)
	}
	format, err := detectFormat(f)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to rewind capture: %w", err)
	}
	handle := &CaptureHandle{File: f, Format: format}
	if format == FormatPCAPNG {
		// The decoder can mask truncated block tails as io.EOF. Validate the
		// full block envelope before trusting any observed packet counts.
		validatedSize, err := validatePCAPNGBlockFraming(f)
		if err != nil {
			return nil, fmt.Errorf("invalid PCAPNG block framing: %w", err)
		}
		// Never read beyond the validated byte extent if the original file
		// is appended after preflight. Identity verification by the caller
		// still rejects in-place edits and append races.
		options.WantMixedLinkType = true
		reader, err := pcapgo.NewNgReader(io.NewSectionReader(f, 0, validatedSize), options)
		if err != nil {
			return nil, fmt.Errorf("failed to create pcapng reader: %w", err)
		}
		handle.Reader = reader
	} else {
		// Check every record's declared caplen and actual extent before the
		// third-party PCAP reader can allocate untrusted packet buffers.
		validatedSize, err := validateClassicPCAPFraming(f)
		if err != nil {
			return nil, fmt.Errorf("invalid PCAP framing: %w", err)
		}
		reader, err := pcapgo.NewReader(io.NewSectionReader(f, 0, validatedSize))
		if err != nil {
			return nil, fmt.Errorf("failed to create pcap reader: %w", err)
		}
		handle.Reader = reader
	}
	return handle, nil
}

// OpenCaptureFromReader creates a PacketReader from an io.Reader when
// the magic bytes have already been consumed (e.g. bytes.Buffer in tests).
// It always creates a pcap reader for backward compatibility with tests.
func OpenCaptureFromReader(r io.Reader) (PacketReader, error) {
	return pcapgo.NewReader(r)
}

// detectFormat reads the first 4 bytes of a file to determine the
// capture format. The caller should seek back to 0 after this call.
func detectFormat(f *os.File) (CaptureFormat, error) {
	var magic uint32
	if err := binary.Read(f, binary.BigEndian, &magic); err != nil {
		return "", fmt.Errorf("failed to read magic bytes (file may be empty or corrupt): %w", err)
	}

	switch magic {
	case pcapMagicBE, pcapMagicLE, pcapMagicNS, pcapMagicNL:
		return FormatPCAP, nil
	case pcapngMagic:
		return FormatPCAPNG, nil
	default:
		return "", fmt.Errorf("unrecognised capture format (magic: 0x%08X). Expected .pcap or .pcapng", magic)
	}
}

// DetectCaptureFormat returns the format of a capture file without
// opening a full reader. Useful for UI/metadata display.
func DetectCaptureFormat(filePath string) (CaptureFormat, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return detectFormat(f)
}
