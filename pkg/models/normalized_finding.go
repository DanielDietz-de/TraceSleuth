package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NormalizedFindingSchemaVersion is experimental. The legacy report is not
// removed, and no detector may advertise this schema as stable before the
// Phase 3 migration and golden/API compatibility gates are finished.
const NormalizedFindingSchemaVersion = "0.1.0-alpha"

type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

type FindingCertainty string

const (
	CertaintyObserved         FindingCertainty = "observed"
	CertaintyStronglyInferred FindingCertainty = "strongly_inferred"
	CertaintyProbable         FindingCertainty = "probable"
	CertaintyPossible         FindingCertainty = "possible"
	CertaintyInformational    FindingCertainty = "informational"
)

// PacketSourceReference identifies an actual packet in a specific capture.
// Optional fields use pointers so interface index zero is distinct from
// unknown and missing timestamps cannot be fabricated as zero-time.
type PacketSourceReference struct {
	CaptureID          string            `json:"capture_id"`
	PacketNumber       uint64            `json:"packet_number"`
	Timestamp          *time.Time        `json:"timestamp,omitempty"`
	CaptureInterfaceID *int              `json:"capture_interface_id,omitempty"`
	CapturePointLabel  string            `json:"capture_point_label,omitempty"`
	Reason             string            `json:"reason"`
	RelevantFields     map[string]string `json:"relevant_fields,omitempty"`
}

// FindingEvidence is a typed and traceable observation, not copied payload
// data. A packet evidence item must reference a real source packet.
type FindingEvidence struct {
	ID          string                 `json:"id"`
	Kind        string                 `json:"kind"`
	Description string                 `json:"description"`
	Packet      *PacketSourceReference `json:"packet,omitempty"`
	Value       *float64               `json:"value,omitempty"`
	Unit        string                 `json:"unit,omitempty"`
}

// ConfidenceAdjustment names a genuine, detector-documented evidence family.
// A family may contribute once; aliases of the same packets cannot inflate
// confidence by being counted repeatedly.
type ConfidenceAdjustment struct {
	EvidenceFamily string   `json:"evidence_family"`
	Delta          int      `json:"delta"`
	Reason         string   `json:"reason"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
}

type ExplainedConfidence struct {
	Base        int                    `json:"base"`
	Adjustments []ConfidenceAdjustment `json:"adjustments"`
	Final       int                    `json:"final"`
}

func (c ExplainedConfidence) Calculated() (int, error) {
	if c.Base < 0 || c.Base > 100 {
		return 0, fmt.Errorf("confidence base %d outside 0..100", c.Base)
	}
	if len(c.Adjustments) == 0 {
		return 0, errors.New("confidence has no documented contributions or penalties")
	}
	// Bounded, detector-defined contributions prevent integer overflow from
	// hostile configurations or unexpectedly large evidence fan-out.
	if len(c.Adjustments) > 1024 {
		return 0, errors.New("too many confidence adjustments")
	}
	sum := c.Base
	seen := make(map[string]struct{}, len(c.Adjustments))
	for _, v := range c.Adjustments {
		if strings.TrimSpace(v.EvidenceFamily) == "" || strings.TrimSpace(v.Reason) == "" {
			return 0, errors.New("confidence adjustment lacks evidence family or reason")
		}
		if _, exists := seen[v.EvidenceFamily]; exists {
			return 0, fmt.Errorf("duplicate evidence family %q", v.EvidenceFamily)
		}
		seen[v.EvidenceFamily] = struct{}{}
		if v.Delta < -100 || v.Delta > 100 {
			return 0, fmt.Errorf("confidence contribution %d outside -100..100", v.Delta)
		}
		sum += v.Delta
	}
	if sum < 0 {
		sum = 0
	}
	if sum > 100 {
		sum = 100
	}
	return sum, nil
}

// DiagnosticFinding is the Phase 3 normalized finding contract. Its
// introductory schema is explicitly alpha and NOT yet the public stable API.
// API adapters and detectors will adopt it in independently tested migrations.
type DiagnosticFinding struct {
	ID                      string                  `json:"id"`
	DetectorID              string                  `json:"detector_id"`
	DetectorVersion         string                  `json:"detector_version"`
	SchemaVersion           string                  `json:"schema_version"`
	Title                   string                  `json:"title"`
	Summary                 string                  `json:"summary"`
	Category                string                  `json:"category"`
	Subcategory             string                  `json:"subcategory,omitempty"`
	Severity                FindingSeverity         `json:"severity"`
	Certainty               FindingCertainty        `json:"certainty"`
	Confidence              ExplainedConfidence     `json:"confidence"`
	FirstSeen               *time.Time              `json:"first_seen,omitempty"`
	LastSeen                *time.Time              `json:"last_seen,omitempty"`
	PacketReferences        []PacketSourceReference `json:"packet_references"`
	Evidence                []FindingEvidence       `json:"evidence"`
	AlternativeExplanations []string                `json:"alternative_explanations"`
	CaptureLimitations      []string                `json:"capture_limitations"`
	WiresharkFilters        []string                `json:"wireshark_filters"`
	RecommendedValidation   []string                `json:"recommended_validation"`
}

// Validate enforces the minimum evidence contract for an emitted finding.
// Evidence-free or temporally ungrounded claims must not pass as diagnoses.
// This is stricter than the inherited report's ad-hoc issue arrays.
func (f DiagnosticFinding) Validate() error {
	if f.SchemaVersion != NormalizedFindingSchemaVersion {
		return fmt.Errorf("unsupported normalized finding schema %q", f.SchemaVersion)
	}
	if f.DetectorID == "" || f.DetectorVersion == "" ||
		f.ID == "" || f.Title == "" || f.Summary == "" || f.Category == "" {
		return errors.New("finding lacks identity, detector version, or description")
	}
	switch f.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
	default:
		return fmt.Errorf("invalid severity %q", f.Severity)
	}
	switch f.Certainty {
	case CertaintyObserved, CertaintyStronglyInferred, CertaintyProbable, CertaintyPossible, CertaintyInformational:
	default:
		return fmt.Errorf("invalid certainty %q", f.Certainty)
	}
	score, err := f.Confidence.Calculated()
	if err != nil {
		return err
	}
	if score != f.Confidence.Final {
		return fmt.Errorf("unexplained confidence: calculated %d, stored %d", score, f.Confidence.Final)
	}
	if f.FirstSeen == nil || f.LastSeen == nil || f.LastSeen.Before(*f.FirstSeen) {
		return errors.New("finding lacks a valid observed time range")
	}
	if len(f.Evidence) == 0 {
		return errors.New("finding lacks evidence")
	}
	evidenceIDs := make(map[string]struct{}, len(f.Evidence))
	for _, ev := range f.Evidence {
		if ev.ID == "" || ev.Kind == "" || ev.Description == "" {
			return errors.New("evidence lacks identity, type or description")
		}
		if _, exists := evidenceIDs[ev.ID]; exists {
			return fmt.Errorf("duplicate evidence ID %q", ev.ID)
		}
		evidenceIDs[ev.ID] = struct{}{}
		if ev.Kind == "packet" && ev.Packet == nil {
			return errors.New("packet evidence without packet source reference")
		}
	}
	for _, adj := range f.Confidence.Adjustments {
		if len(adj.EvidenceIDs) == 0 {
			return fmt.Errorf("confidence family %q lacks supporting evidence IDs", adj.EvidenceFamily)
		}
		for _, id := range adj.EvidenceIDs {
			if _, ok := evidenceIDs[id]; !ok {
				return fmt.Errorf("confidence adjustment references unknown evidence %q", id)
			}
		}
	}
	if len(f.PacketReferences) == 0 || len(f.WiresharkFilters) == 0 ||
		len(f.RecommendedValidation) == 0 {
		return errors.New("finding lacks packet references or independent validation")
	}
	for _, p := range f.PacketReferences {
		if p.CaptureID == "" || p.PacketNumber == 0 || p.Reason == "" {
			return errors.New("untraceable packet source reference")
		}
	}
	if f.Certainty != CertaintyObserved && f.Certainty != CertaintyInformational &&
		len(f.AlternativeExplanations) == 0 {
		return errors.New("inferred finding omits alternative explanations")
	}
	return nil
}

// StableFindingID is derived from machine-semantic context and packet
// references, never Go map iteration or localized presentation strings.
// It must only be called with source packet references established by the
// capture reader; this helper does not invent evidence.
func StableFindingID(detectorID, detectorVersion, category string, refs []PacketSourceReference) (string, error) {
	if detectorID == "" || detectorVersion == "" || category == "" || len(refs) == 0 {
		return "", errors.New("finding identity requires detector and packet references")
	}
	// Serialize only machine-semantic identifiers. Human-language reasons
	// and localized presentation text must never change finding identity.
	// JSON sorts map keys; sorting the serialized references also handles
	// otherwise-equal packet IDs with different observed protocol fields.
	type sourceIdentity struct {
		CaptureID          string            `json:"capture_id"`
		PacketNumber       uint64            `json:"packet_number"`
		Timestamp          *time.Time        `json:"timestamp,omitempty"`
		CaptureInterfaceID *int              `json:"capture_interface_id,omitempty"`
		RelevantFields     map[string]string `json:"relevant_fields,omitempty"`
	}
	canonical := make([]string, 0, len(refs))
	for _, p := range refs {
		if p.CaptureID == "" || p.PacketNumber == 0 {
			return "", errors.New("cannot identify an untraceable packet")
		}
		src, err := json.Marshal(sourceIdentity{
			CaptureID: p.CaptureID, PacketNumber: p.PacketNumber,
			Timestamp: p.Timestamp, CaptureInterfaceID: p.CaptureInterfaceID,
			RelevantFields: p.RelevantFields,
		})
		if err != nil {
			return "", fmt.Errorf("marshal packet identity: %w", err)
		}
		canonical = append(canonical, string(src))
	}
	sort.Strings(canonical)
	blob, err := json.Marshal(struct {
		DetectorID      string   `json:"detector_id"`
		DetectorVersion string   `json:"detector_version"`
		Category        string   `json:"category"`
		Packets         []string `json:"packets"`
	}{detectorID, detectorVersion, category, canonical})
	if err != nil {
		return "", fmt.Errorf("marshal finding identity: %w", err)
	}
	digest := sha256.Sum256(blob)
	return hex.EncodeToString(digest[:]), nil
}
