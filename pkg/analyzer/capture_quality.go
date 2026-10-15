package analyzer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Minimum complete on-wire byte depths for protocol observability. A link
// type by itself cannot establish that a capture retains protocol headers.
const (
	minEthernetFrameDepth uint32 = 14
	minVLANTagDepth       uint32 = 18
	minSTPBPDUDepth       uint32 = 52  // Ethernet + 802.3 LLC + standard BPDU
	minLACPDUDepth        uint32 = 124 // Ethernet + LACPDU
)

const timestampGapThreshold = 30 * time.Second

// The pinned gopacket v1.1.19 Reader.Resolution() reverses microsecond
// and nanosecond for classic PCAP. Use the original magic on the already-open
// descriptor instead; ReadAt does not perturb the packet reader's position.
func classicPCAPResolution(file *os.File) (string, error) {
	var magic [4]byte
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return "", fmt.Errorf("read capture timestamp resolution: %w", err)
	}
	switch binary.BigEndian.Uint32(magic[:]) {
	case pcapMagicBE, pcapMagicLE:
		return gopacket.TimestampResolutionMicrosecond.String(), nil
	case pcapMagicNS, pcapMagicNL:
		return gopacket.TimestampResolutionNanosecond.String(), nil
	default:
		return "", fmt.Errorf("unknown classic capture magic")
	}
}

// InspectCapture is the metadata-only form of InspectCaptureAndOpen. The
// caller does not own a capture descriptor when this function returns.
func InspectCapture(path string) (*models.CaptureQuality, error) {
	q, capture, err := InspectCaptureAndOpen(path)
	if err != nil {
		return nil, err
	}
	defer capture.Close()
	return q, nil
}

// InspectCaptureAndOpen inspects and returns a reader for the SAME descriptor.
//
// A pathname can be atomically replaced during analysis; reopening by name
// could otherwise produce findings unrelated to the capture SHA-256. All
// passes here use the same file descriptor. The bytes are verified against
// the preflight digest before the reader is returned and must be verified
// once more after detectors finish, in case the file was modified in place.
// Callers own the returned handle and must close it.
func InspectCaptureAndOpen(path string) (*models.CaptureQuality, *CaptureHandle, error) {
	// Hash and parse only the private working snapshot. The concurrently
	// mutable input descriptor is preserved solely for identity verification.
	cap, digest, size, err := openImmutableCapture(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open capture preflight: %w", err)
	}
	file := cap.File
	q := &models.CaptureQuality{
		SHA256:        digest,
		FileSizeBytes: size,
		Status:        "good",
		Interfaces:    make([]models.CaptureInterface, 0, 1),
		LinkTypes:     make([]string, 0, 1),
		Capabilities:  make([]string, 0, 4),
		Limitations:   make([]models.CaptureQualityIssue, 0),
	}
	linkTypeSet := map[string]bool{}
	interfacePackets := map[int]uint64{}
	interfaceTruncatedDepth := map[int]uint32{}
	interfaceTruncated := map[int]bool{}
	var usableEthernetDepth uint32
	activeEthernetInterfaces := 0
	// A single deeper interface must not conceal a shallow one. Capabilities
	// require that EVERY active Ethernet capture point can observe the header.
	observeEthernetDepth := func(sectionIndex, ifaceIndex int, snapLength, truncatedBytes uint32, truncated bool) {
		// Capacity is determined by capture snaplen, not the length of ordinary
		// traffic seen. A short untruncated frame does not prove a LACP frame
		// would have been truncated. PCAPNG snaplen=0 means unlimited.
		depth := snapLength
		if depth == 0 {
			depth = ^uint32(0)
		}
		if truncated && truncatedBytes < depth {
			depth = truncatedBytes
		}
		if activeEthernetInterfaces == 0 || depth < usableEthernetDepth {
			usableEthernetDepth = depth
		}
		activeEthernetInterfaces++
		if depth < minLACPDUDepth {
			severity := "informational"
			if depth < minSTPBPDUDepth || (snapLength != 0 && snapLength < minLACPDUDepth) {
				severity = "warning"
				q.Status = "degraded"
			}
			q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
				Code:     "insufficient_layer2_capture_depth",
				Severity: severity,
				Description: fmt.Sprintf(
					"Capture section %d interface %d has an effective capture depth of at most %d Ethernet bytes (snap length %d); full STP/LACP evidence may be unavailable on this capture point.",
					sectionIndex, ifaceIndex, depth, snapLength,
				),
			})
		}
	}
	section := 0
	anyCaptureFilter := false
	// An interface without an Interface Statistics Block has UNKNOWN drops,
	// not a reported zero. The reader initializes absent stats to zero values.
	// Keep the maximum known drop count from ALL statistics blocks.
	// NgReader replaces its per-interface statistics on each ISB, so a
	// later block with an omitted counter must not erase an earlier loss.
	reportedDrops := map[int]uint64{}

	// NgReader's interface indices restart at each section. Its callback
	// supplies the completed section before clearing the old interface list.
	// Preserve metadata per section rather than attributing all packet counts
	// to the LAST section's interfaces.
	finishSection := func(interfaces []pcapgo.NgInterface) {
		for idx, iface := range interfaces {
			if iface.LinkType == layers.LinkTypeEthernet && interfacePackets[idx] > 0 {
				observeEthernetDepth(section, idx, iface.SnapLength, interfaceTruncatedDepth[idx], interfaceTruncated[idx])
			}
			info := models.CaptureInterface{
				SectionIndex: section,
				Index:        idx, Name: iface.Name, LinkType: iface.LinkType.String(),
				Filter: iface.Filter, SnapLength: iface.SnapLength,
				TimestampResolution: fmt.Sprint(iface.Resolution()),
				PacketCount:         interfacePackets[idx],
			}
			if iface.Filter != "" {
				anyCaptureFilter = true
				q.Status = "degraded"
				q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
					Code: "interface_capture_filter", Severity: "warning",
					Description: fmt.Sprintf("Capture section %d interface %d used a packet filter. Protocols excluded by the filter are not observable.", section, idx),
				})
			}
			if drops, known := reportedDrops[idx]; known {
				info.ReportedDrops = &drops
				if drops > 0 {
					q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
						Code: "capture_reported_drops", Severity: "warning", Count: drops,
						Description: fmt.Sprintf("Capture section %d interface %d (%q) reported %d packet drops; absence of packets is not conclusive evidence of network loss.", section, idx, iface.Name, drops),
					})
					q.Status = "degraded"
				}
			}
			q.Interfaces = append(q.Interfaces, info)
		}
		section++
		interfacePackets = make(map[int]uint64)
		interfaceTruncatedDepth = make(map[int]uint32)
		interfaceTruncated = make(map[int]bool)
		reportedDrops = make(map[int]uint64)
	}

	// SectionEndCallback does not fire for the final section on EOF.
	opts := pcapgo.NgReaderOptions{
		WantMixedLinkType: true,
		SectionEndCallback: func(ifaces []pcapgo.NgInterface, _ pcapgo.NgSectionInfo) {
			finishSection(ifaces)
		},
		StatisticsCallback: func(index int, stats pcapgo.NgInterfaceStatistics) {
			if stats.PacketsDropped == pcapgo.NgNoValue64 {
				return
			}
			if existing, seen := reportedDrops[index]; !seen || stats.PacketsDropped > existing {
				reportedDrops[index] = stats.PacketsDropped
			}
		},
	}
	parsed, err := openCaptureOnFile(file, opts)
	if err != nil {
		_ = cap.Close()
		return nil, nil, fmt.Errorf("capture preflight: %w", err)
	}
	cap.Reader, cap.Format = parsed.Reader, parsed.Format
	fail := func(err error) (*models.CaptureQuality, *CaptureHandle, error) {
		_ = cap.Close()
		return nil, nil, err
	}
	q.Format = string(cap.Format)

	var first, last, prev time.Time
	for {
		data, ci, err := cap.Reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Preserve a safe packet index for both CLI and HTTP callers even
			// when the shared preflight catches corruption before comparison.
			// Never expose server-owned upload paths in the error text.
			return fail(&MalformedCaptureRecordError{Index: int(q.PacketCount), Cause: err})
		}
		q.PacketCount++
		q.CapturedBytes += uint64(len(data))
		q.OriginalBytes += uint64(ci.Length)
		if ci.CaptureLength < ci.Length {
			q.TruncatedPackets++
			// Only a genuinely truncated record limits inferred capture depth.
			// An unrelated full-sized frame must not conceal a shallow drop.
			if !interfaceTruncated[ci.InterfaceIndex] || uint32(len(data)) < interfaceTruncatedDepth[ci.InterfaceIndex] {
				interfaceTruncatedDepth[ci.InterfaceIndex] = uint32(len(data))
			}
			interfaceTruncated[ci.InterfaceIndex] = true
		}
		interfacePackets[ci.InterfaceIndex]++
		linkType := cap.Reader.LinkType()
		for _, extra := range ci.AncillaryData {
			if lt, ok := extra.(layers.LinkType); ok {
				linkType = lt
			}
		}
		linkTypeSet[linkType.String()] = true
		ts := ci.Timestamp
		if ts.IsZero() {
			q.MissingTimestamps++
			continue
		}
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if last.IsZero() || ts.After(last) {
			last = ts
		}
		if !prev.IsZero() {
			if ts.Before(prev) {
				q.NonMonotonicTimestamps++
			} else if ts.Sub(prev) > timestampGapThreshold {
				q.LargeTimestampGaps++
			}
		}
		prev = ts
	}
	if ng, ok := cap.Reader.(*pcapgo.NgReader); ok {
		interfaces := make([]pcapgo.NgInterface, 0, ng.NInterfaces())
		for i := 0; i < ng.NInterfaces(); i++ {
			iface, err := ng.Interface(i)
			if err != nil {
				q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
					Code: "interface_metadata_unavailable", Severity: "warning",
					Description: fmt.Sprintf("Metadata for capture section %d interface %d could not be read.", section, i),
				})
				q.Status = "degraded"
				continue
			}
			interfaces = append(interfaces, iface)
		}
		finishSection(interfaces)
	} else if classic, ok := cap.Reader.(*pcapgo.Reader); ok {
		resolution, err := classicPCAPResolution(cap.File)
		if err != nil {
			return fail(err)
		}
		if classic.LinkType() == layers.LinkTypeEthernet && interfacePackets[0] > 0 {
			observeEthernetDepth(0, 0, classic.Snaplen(), interfaceTruncatedDepth[0], interfaceTruncated[0])
		}
		q.Interfaces = append(q.Interfaces, models.CaptureInterface{
			SectionIndex: 0, Index: 0, LinkType: classic.LinkType().String(),
			SnapLength: classic.Snaplen(), TimestampResolution: resolution,
			PacketCount: interfacePackets[0],
		})
	}
	if q.PacketCount == 0 {
		return fail(fmt.Errorf("capture preflight: no packets present"))
	}
	if !first.IsZero() {
		q.FirstTimestamp = &first
		q.LastTimestamp = &last
		q.DurationSeconds = last.Sub(first).Seconds()
	}
	q.TruncationRate = float64(q.TruncatedPackets) / float64(q.PacketCount)
	for lt := range linkTypeSet {
		q.LinkTypes = append(q.LinkTypes, lt)
	}
	sort.Strings(q.LinkTypes)

	if linkTypeSet[layers.LinkTypeEthernet.String()] {
		if usableEthernetDepth >= minEthernetFrameDepth {
			q.Capabilities = append(q.Capabilities, "ethernet")
		}
		if usableEthernetDepth >= minVLANTagDepth {
			q.Capabilities = append(q.Capabilities, "vlan")
		}
		// Packet filters may hide whole protocols even if the file has enough
		// snap length to decode them. Only advertise *usable* capabilities.
		if !anyCaptureFilter && usableEthernetDepth >= minSTPBPDUDepth {
			q.Capabilities = append(q.Capabilities, "stp_bpdu")
		}
		if !anyCaptureFilter && usableEthernetDepth >= minLACPDUDepth {
			q.Capabilities = append(q.Capabilities, "lacp_slow_protocols")
		}
	} else {
		q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
			Code: "ethernet_not_observable", Severity: "warning",
			Description: "No Ethernet link type was observed; Ethernet, STP and LACP diagnoses cannot be validated from this capture.",
		})
		q.Status = "degraded"
	}

	if q.TruncatedPackets > 0 {
		q.Status = "degraded"
		q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
			Code: "truncated_packets", Severity: "warning", Count: q.TruncatedPackets,
			Description: "Some packets contain fewer captured bytes than their original wire length; protocol details may be missing.",
		})
	}
	if q.NonMonotonicTimestamps > 0 {
		q.Status = "degraded"
		q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
			Code: "nonmonotonic_timestamps", Severity: "warning", Count: q.NonMonotonicTimestamps,
			Description: "Packet timestamps moved backwards; rate and causal timing analysis may be unreliable.",
		})
	}
	if q.MissingTimestamps > 0 {
		q.Status = "degraded"
		q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
			Code: "missing_timestamps", Severity: "warning", Count: q.MissingTimestamps,
			Description: "Some packets have no usable timestamp; duration and delay calculations are incomplete.",
		})
	}
	if q.LargeTimestampGaps > 0 {
		q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
			Code: "capture_time_gaps", Severity: "informational", Count: q.LargeTimestampGaps,
			Description: "Long intervals without captured packets may reflect idle traffic, filters or capture interruptions.",
		})
	}

	// A file may be modified in place during preflight. Invalidate the result
	// before any analyzer consumes it if the bytes changed.
	if err := VerifyCaptureHandle(cap, q); err != nil {
		return fail(fmt.Errorf("capture changed during preflight: %w", err))
	}
	// Reset the decoder on exactly the same private, validated bytes.
	// The original descriptor remains open only to detect source mutations.
	parsed, err = openCaptureOnFile(file, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		return fail(fmt.Errorf("failed to rewind verified capture: %w", err))
	}
	cap.Reader, cap.Format = parsed.Reader, parsed.Format
	return q, cap, nil
}

// hashCaptureWithinLimit reads at most expected+1 bytes, even if the source
// is continuously being appended by another process. The extra byte detects
// an append without letting untrusted input stall capture verification.
func hashCaptureWithinLimit(source io.Reader, expected int64) (int64, string, error) {
	if expected < 0 || expected > maxSnapshotBytes {
		return 0, "", fmt.Errorf("invalid capture identity length %d", expected)
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(source, expected+1))
	return n, hex.EncodeToString(hash.Sum(nil)), err
}

// VerifyCaptureHandle checks both the byte count and content SHA-256 on the
// original descriptor. It intentionally invalidates the reader position and
// must only be called after a preflight/analysis pass is complete.
func VerifyCaptureHandle(cap *CaptureHandle, quality *models.CaptureQuality) error {
	if cap == nil || cap.File == nil || quality == nil {
		return fmt.Errorf("missing capture descriptor or identity")
	}
	if _, err := cap.File.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind for identity verification: %w", err)
	}
	n, digest, err := hashCaptureWithinLimit(cap.File, quality.FileSizeBytes)
	if err != nil {
		return fmt.Errorf("verify capture hash: %w", err)
	}
	if n != quality.FileSizeBytes || digest != quality.SHA256 {
		return fmt.Errorf("capture working copy differs from preflight digest")
	}
	if cap.SourceFile != nil {
		if _, err := cap.SourceFile.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind original capture for identity verification: %w", err)
		}
		originalSize, originalDigest, err := hashCaptureWithinLimit(cap.SourceFile, quality.FileSizeBytes)
		if err != nil {
			return fmt.Errorf("hash original capture: %w", err)
		}
		if originalSize != quality.FileSizeBytes || originalDigest != quality.SHA256 {
			return fmt.Errorf("original capture changed during analysis")
		}
	}
	return nil
}

// CaptureIdentity retains the path-based verification helper for use when
// validating an external input independently. Analysis uses descriptor-based
// VerifyCaptureHandle instead, avoiding rename-to-different-file races.
func CaptureIdentity(path, expectedSHA256 string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}
	return hex.EncodeToString(hash.Sum(nil)) == expectedSHA256, nil
}
