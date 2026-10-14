package models

import "time"

// CaptureQuality describes what was actually present and observable in the
// capture before network fault detectors run. Counts and timestamps are
// observations; limitations are not diagnoses of the live network.
type CaptureQuality struct {
	SHA256                 string                `json:"sha256"`
	Format                 string                `json:"format"`
	FileSizeBytes          int64                 `json:"file_size_bytes"`
	PacketCount            uint64                `json:"packet_count"`
	CapturedBytes          uint64                `json:"captured_bytes"`
	OriginalBytes          uint64                `json:"original_bytes"`
	TruncatedPackets       uint64                `json:"truncated_packets"`
	TruncationRate         float64               `json:"truncation_rate"`
	NonMonotonicTimestamps uint64                `json:"non_monotonic_timestamps"`
	MissingTimestamps      uint64                `json:"missing_timestamps"`
	LargeTimestampGaps     uint64                `json:"large_timestamp_gaps"`
	FirstTimestamp         *time.Time            `json:"first_timestamp,omitempty"`
	LastTimestamp          *time.Time            `json:"last_timestamp,omitempty"`
	DurationSeconds        float64               `json:"duration_seconds"`
	Interfaces             []CaptureInterface    `json:"interfaces"`
	LinkTypes              []string              `json:"link_types"`
	Capabilities           []string              `json:"capabilities"`
	Limitations            []CaptureQualityIssue `json:"limitations"`
	Status                 string                `json:"status"` // good or degraded; malformed captures fail preflight
}

type CaptureInterface struct {
	Index               int     `json:"index"`
	Name                string  `json:"name,omitempty"`
	LinkType            string  `json:"link_type"`
	SnapLength          uint32  `json:"snap_length"`
	TimestampResolution string  `json:"timestamp_resolution,omitempty"`
	PacketCount         uint64  `json:"packet_count"`
	ReportedDrops       *uint64 `json:"reported_drops,omitempty"`
}

type CaptureQualityIssue struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"` // warning or informational
	Count       uint64 `json:"count,omitempty"`
	Description string `json:"description"`
}
