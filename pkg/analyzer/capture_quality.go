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
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const timestampGapThreshold = 30 * time.Second

// InspectCapture computes a bounded-memory, format-aware preflight over the
// complete capture. It runs before network detectors for both CLI and web
// analysis, and rejects empty or structurally truncated files. No packet
// payload or credential material is retained in the quality result.
func InspectCapture(path string) (*models.CaptureQuality, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture preflight: %w", err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("hash capture: %w", err)
	}

	cap, err := OpenCapture(path)
	if err != nil {
		return nil, fmt.Errorf("capture preflight: %w", err)
	}
	defer cap.Close()

	q := &models.CaptureQuality{
		SHA256: hex.EncodeToString(hash.Sum(nil)),
		Format: string(cap.Format),
		FileSizeBytes: size,
		Status: "good",
		Interfaces: make([]models.CaptureInterface, 0, 1),
		LinkTypes: make([]string, 0, 1),
		Capabilities: make([]string, 0, 4),
		Limitations: make([]models.CaptureQualityIssue, 0),
	}
	linkTypeSet := map[string]bool{}
	interfacePackets := map[int]uint64{}
	var first, last, prev time.Time
	for {
		data, ci, err := cap.Reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("capture contains malformed/truncated packet record after %d packets: %w", q.PacketCount, err)
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
				linkType = lt // mixed-link-type pcapng provides per-packet link type
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

	if q.PacketCount == 0 {
		return nil, fmt.Errorf("capture preflight: no packets present")
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
	// Ethernet is necessary to observe standard Ethernet-level STP,
	// LACP and forwarding-loop symptoms. Presence does not establish cause.
	if linkTypeSet[layers.LinkTypeEthernet.String()] {
		q.Capabilities = append(q.Capabilities, "ethernet", "vlan", "stp_bpdu", "lacp_slow_protocols")
	} else {
		q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
			Code: "ethernet_not_observable", Severity: "warning",
			Description: "No Ethernet link type was observed; Ethernet, STP and LACP diagnoses cannot be validated from this capture.",
		})
		q.Status = "degraded"
	}

	if ng, ok := cap.Reader.(*pcapgo.NgReader); ok {
		for i := 0; i < ng.NInterfaces(); i++ {
			iface, err := ng.Interface(i)
			if err != nil {
				q.Limitations = append(q.Limitations, models.CaptureQualityIssue{
					Code: "interface_metadata_unavailable", Severity: "warning",
					Description: "Capture interface metadata could not be read.",
				})
				q.Status = "degraded"
				continue
			}
			info := models.CaptureInterface{
				Index: i, Name: iface.Name, LinkType: iface.LinkType.String(),
				SnapLength: iface.SnapLength,
				TimestampResolution: fmt.Sprint(iface.Resolution()),
				PacketCount: interfacePackets[i],
			}
			if iface.Statistics.PacketsDropped != pcapgo.NgNoValue64 {
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
	} else if classic, ok := cap.Reader.(*pcapgo.Reader); ok {
		q.Interfaces = append(q.Interfaces, models.CaptureInterface{
			Index: 0, LinkType: classic.LinkType().String(),
			SnapLength: classic.Snaplen(), TimestampResolution: fmt.Sprint(classic.Resolution()),
			PacketCount: interfacePackets[0],
		})
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
	return q, nil
}

// CaptureIdentity verifies the source file content against the preflight
// digest before interpreting results, defending against file replacement.
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

// The packet-reader types satisfy the common preflight interface.
var _ PacketReader = (*pcapgo.Reader)(nil)
var _ PacketReader = (*pcapgo.NgReader)(nil)
var _ = gopacket.CaptureInfo{}
