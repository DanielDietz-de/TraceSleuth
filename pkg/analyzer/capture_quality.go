package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const timestampGapThreshold = 30 * time.Second

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
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open capture preflight: %w", err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("hash capture: %w", err)
	}

	q := &models.CaptureQuality{
		SHA256:        hex.EncodeToString(hash.Sum(nil)),
		FileSizeBytes: size,
		Status:        "good",
		Interfaces:    make([]models.CaptureInterface, 0, 1),
		LinkTypes:     make([]string, 0, 1),
		Capabilities:  make([]string, 0, 4),
		Limitations:   make([]models.CaptureQualityIssue, 0),
	}
	linkTypeSet := map[string]bool{}
	interfacePackets := map[int]uint64{}
	section := 0
	anyCaptureFilter := false
	// An interface without an Interface Statistics Block has UNKNOWN drops,
	// not a reported zero. The reader initializes absent stats to zero values.
	statsObserved := map[int]bool{}

	// NgReader's interface indices restart at each section. Its callback
	// supplies the completed section before clearing the old interface list.
	// Preserve metadata per section rather than attributing all packet counts
	// to the LAST section's interfaces.
	finishSection := func(interfaces []pcapgo.NgInterface) {
		for idx, iface := range interfaces {
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
			if statsObserved[idx] && iface.Statistics.PacketsDropped != pcapgo.NgNoValue64 {
				drops := iface.Statistics.PacketsDropped
				info.ReportedDrops = &drops
				if drops > 0 {
					q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
						Code: "capture_reported_drops", Severity: "warning", Count: drops,
						Description: "The capture interface reported packet drops; absence of packets is not conclusive evidence of network loss.",
					})
					q.Status = "degraded"
				}
			}
			q.Interfaces = append(q.Interfaces, info)
		}
		section++
		interfacePackets = make(map[int]uint64)
		statsObserved = make(map[int]bool)
	}

	// SectionEndCallback does not fire for the final section on EOF.
	opts := pcapgo.NgReaderOptions{
		WantMixedLinkType: true,
		SectionEndCallback: func(ifaces []pcapgo.NgInterface, _ pcapgo.NgSectionInfo) {
			finishSection(ifaces)
		},
		StatisticsCallback: func(index int, _ pcapgo.NgInterfaceStatistics) {
			statsObserved[index] = true
		},
	}
	cap, err := openCaptureOnFile(file, opts)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("capture preflight: %w", err)
	}
	fail := func(err error) (*models.CaptureQuality, *CaptureHandle, error) {
		cap.Close()
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
			return fail(fmt.Errorf("capture contains malformed/truncated packet record after %d packets: %w", q.PacketCount, err))
		}
		q.PacketCount++
		q.CapturedBytes += uint64(len(data))
		q.OriginalBytes += uint64(ci.Length)
		if ci.CaptureLength < ci.Length {
			q.TruncatedPackets++
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
		q.Interfaces = append(q.Interfaces, models.CaptureInterface{
			SectionIndex: 0, Index: 0, LinkType: classic.LinkType().String(),
			SnapLength: classic.Snaplen(), TimestampResolution: fmt.Sprint(classic.Resolution()),
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
		q.Capabilities = append(q.Capabilities, "ethernet", "vlan")
		// Interface filters may suppress every STP/LACP packet. Even a valid
		// Ethernet capture with an active filter is not an unfiltered view.
		if !anyCaptureFilter {
			q.Capabilities = append(q.Capabilities, "stp_bpdu", "lacp_slow_protocols")
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
	// The detection pass consumes the same descriptor, reset to byte zero.
	cap, err = openCaptureOnFile(file, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("failed to rewind verified capture: %w", err)
	}
	return q, cap, nil
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
	sum := sha256.New()
	n, err := io.Copy(sum, cap.File)
	if err != nil {
		return fmt.Errorf("verify capture hash: %w", err)
	}
	if n != quality.FileSizeBytes || hex.EncodeToString(sum.Sum(nil)) != quality.SHA256 {
		return fmt.Errorf("capture contents differ from preflight digest")
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
