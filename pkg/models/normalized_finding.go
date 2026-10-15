package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
	CaptureID           string            `json:"capture_id"`
	PacketNumber        uint64            `json:"packet_number"`
	Timestamp           *time.Time        `json:"timestamp,omitempty"`
	CaptureSectionIndex *int              `json:"capture_section_index,omitempty"`
	CaptureInterfaceID  *int              `json:"capture_interface_id,omitempty"`
	CapturePointLabel   string            `json:"capture_point_label,omitempty"`
	Reason              string            `json:"reason"`
	RelevantFields      map[string]string `json:"relevant_fields,omitempty"`
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
		family := strings.TrimSpace(v.EvidenceFamily)
		if family == "" || strings.TrimSpace(v.Reason) == "" {
			return 0, errors.New("confidence adjustment lacks evidence family or reason")
		}
		if _, exists := seen[family]; exists {
			return 0, fmt.Errorf("duplicate evidence family %q", family)
		}
		seen[family] = struct{}{}
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

// validPacketSource checks actual capture and packet provenance without
// treating interface zero as absent. No packet reference is synthesized.
func validPacketSource(p PacketSourceReference) error {
	if strings.TrimSpace(p.CaptureID) == "" || p.PacketNumber == 0 || strings.TrimSpace(p.Reason) == "" {
		return errors.New("untraceable packet source reference")
	}
	// Capture aliases must not bypass packet-evidence deduplication.
	if p.CaptureID != strings.TrimSpace(p.CaptureID) {
		return errors.New("non-canonical capture identifier")
	}
	if (p.CaptureInterfaceID == nil) != (p.CaptureSectionIndex == nil) {
		return errors.New("packet source must specify capture section and interface together")
	}
	if p.CaptureSectionIndex != nil && *p.CaptureSectionIndex < 0 {
		return errors.New("negative capture section identifier")
	}
	if p.CaptureInterfaceID != nil && *p.CaptureInterfaceID < 0 {
		return errors.New("negative capture interface identifier")
	}
	if p.Timestamp != nil {
		if p.Timestamp.IsZero() {
			return errors.New("packet source has a zero timestamp")
		}
		if _, err := p.Timestamp.MarshalJSON(); err != nil {
			return fmt.Errorf("packet source timestamp is not JSON-serializable: %w", err)
		}
	}
	return nil
}

// hasNonemptyEntries ensures independently actionable validation content.
// A slice containing blank strings is no better than an absent field.
func hasNonemptyEntries(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			return false
		}
	}
	return true
}

// Validate enforces the minimum evidence contract for an emitted finding.
// Evidence-free or temporally ungrounded claims must not pass as diagnoses.
// This is stricter than the inherited report's ad-hoc issue arrays.
func (f DiagnosticFinding) Validate() error {
	if f.SchemaVersion != NormalizedFindingSchemaVersion {
		return fmt.Errorf("unsupported normalized finding schema %q", f.SchemaVersion)
	}
	if strings.TrimSpace(f.DetectorID) == "" || strings.TrimSpace(f.DetectorVersion) == "" ||
		strings.TrimSpace(f.ID) == "" || strings.TrimSpace(f.Title) == "" ||
		strings.TrimSpace(f.Summary) == "" || strings.TrimSpace(f.Category) == "" {
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
	// A single positive observation and a penalty cannot establish strong
	// inference; this level requires two independent supporting families.
	if f.Certainty == CertaintyStronglyInferred {
		positiveFamilies := 0
		for _, adjustment := range f.Confidence.Adjustments {
			if adjustment.Delta > 0 {
				positiveFamilies++
			}
		}
		if positiveFamilies < 2 {
			return errors.New("strong inference requires two independent positive evidence families")
		}
	}
	if f.FirstSeen == nil || f.LastSeen == nil || f.FirstSeen.IsZero() ||
		f.LastSeen.IsZero() || f.LastSeen.Before(*f.FirstSeen) {
		return errors.New("finding lacks a valid observed time range")
	}
	// A valid finding must be serializable; Go rejects RFC3339 years outside
	// 0000..9999 and invalid timezone offsets during JSON marshaling.
	for _, timestamp := range []*time.Time{f.FirstSeen, f.LastSeen} {
		if _, err := timestamp.MarshalJSON(); err != nil {
			return fmt.Errorf("finding time range is not JSON-serializable: %w", err)
		}
	}
	if len(f.Evidence) == 0 {
		return errors.New("finding lacks evidence")
	}
	evidenceByID := make(map[string]FindingEvidence, len(f.Evidence))
	for _, ev := range f.Evidence {
		if strings.TrimSpace(ev.ID) == "" || strings.TrimSpace(ev.Kind) == "" ||
			strings.TrimSpace(ev.Description) == "" {
			return errors.New("evidence lacks identity, type or description")
		}
		// Reject whitespace aliases rather than letting them bypass the
		// type-specific validation for packet and metric evidence.
		if ev.Kind != strings.TrimSpace(ev.Kind) {
			return fmt.Errorf("evidence %q has a non-canonical kind %q", ev.ID, ev.Kind)
		}
		// Noncanonical IDs can double-count one metric under different names.
		if ev.ID != strings.TrimSpace(ev.ID) {
			return fmt.Errorf("non-canonical evidence ID %q", ev.ID)
		}
		if _, exists := evidenceByID[ev.ID]; exists {
			return fmt.Errorf("duplicate evidence ID %q", ev.ID)
		}
		if ev.Value != nil && (math.IsNaN(*ev.Value) || math.IsInf(*ev.Value, 0)) {
			return fmt.Errorf("evidence %q contains a non-finite value", ev.ID)
		}
		if ev.Packet != nil {
			if err := validPacketSource(*ev.Packet); err != nil {
				return fmt.Errorf("invalid packet evidence %q: %w", ev.ID, err)
			}
		}
		switch ev.Kind {
		case "packet":
			if ev.Packet == nil {
				return errors.New("packet evidence without packet source reference")
			}
		case "metric":
			if ev.Value == nil || strings.TrimSpace(ev.Unit) == "" {
				return fmt.Errorf("metric evidence %q lacks a finite value and unit", ev.ID)
			}
		}
		evidenceByID[ev.ID] = ev
	}
	usedConfidenceEvidence := make(map[string]struct{}, len(f.Evidence))
	// A single capture/packet observation is not independent evidence merely
	// because it was assigned different IDs or described by different fields.
	type packetIdentity struct {
		captureID    string
		packetNumber uint64
	}
	usedPacketEvidence := make(map[packetIdentity]string, len(f.Evidence))
	for _, adj := range f.Confidence.Adjustments {
		if len(adj.EvidenceIDs) == 0 {
			return fmt.Errorf("confidence family %q lacks supporting evidence IDs", adj.EvidenceFamily)
		}
		family := strings.TrimSpace(adj.EvidenceFamily)
		for _, id := range adj.EvidenceIDs {
			ev, ok := evidenceByID[id]
			if !ok {
				return fmt.Errorf("confidence adjustment references unknown evidence %q", id)
			}
			if _, used := usedConfidenceEvidence[id]; used {
				return fmt.Errorf("confidence reuses evidence %q across contributions", id)
			}
			usedConfidenceEvidence[id] = struct{}{}
			if ev.Packet != nil {
				key := packetIdentity{captureID: ev.Packet.CaptureID, packetNumber: ev.Packet.PacketNumber}
				if previousFamily, used := usedPacketEvidence[key]; used && previousFamily != family {
					return fmt.Errorf("packet %d from capture %q is counted in multiple confidence families", key.packetNumber, key.captureID)
				}
				usedPacketEvidence[key] = family
			}
		}
	}
	if len(f.PacketReferences) == 0 || !hasNonemptyEntries(f.WiresharkFilters) ||
		!hasNonemptyEntries(f.RecommendedValidation) {
		return errors.New("finding lacks packet references or independent validation")
	}
	// Confidence-supporting packets must be present in the top-level
	// navigable packet references from which the finding ID is derived.
	packetRefs := make(map[packetIdentity][]PacketSourceReference, len(f.PacketReferences))
	for _, p := range f.PacketReferences {
		if err := validPacketSource(p); err != nil {
			return err
		}
		key := packetIdentity{captureID: p.CaptureID, packetNumber: p.PacketNumber}
		packetRefs[key] = append(packetRefs[key], p)
	}
	for _, evidence := range f.Evidence {
		if evidence.Packet == nil {
			continue
		}
		key := packetIdentity{captureID: evidence.Packet.CaptureID, packetNumber: evidence.Packet.PacketNumber}
		matching := false
		for _, reference := range packetRefs[key] {
			if sameOptionalInt(reference.CaptureSectionIndex, evidence.Packet.CaptureSectionIndex) &&
				sameOptionalInt(reference.CaptureInterfaceID, evidence.Packet.CaptureInterfaceID) &&
				sameOptionalInstant(reference.Timestamp, evidence.Packet.Timestamp) {
				matching = true
				break
			}
		}
		if !matching {
			return fmt.Errorf("evidence %q cites a packet not present in finding packet references", evidence.ID)
		}
	}
	if f.Certainty != CertaintyObserved && f.Certainty != CertaintyInformational {
		if !hasNonemptyEntries(f.AlternativeExplanations) || !hasNonemptyEntries(f.CaptureLimitations) {
			return errors.New("inferred finding omits substantive alternatives or capture limitations")
		}
	}
	// IDs are content-derived; changing the detector/category/packet
	// identity after assigning an ID must invalidate the finding.
	expectedID, err := StableFindingID(f.DetectorID, f.DetectorVersion, f.Category, f.PacketReferences)
	if err != nil {
		return fmt.Errorf("invalid finding identity: %w", err)
	}
	if f.ID != expectedID {
		return errors.New("finding ID does not match detector, category and packet identity")
	}
	return nil
}

func sameOptionalInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameOptionalInstant(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// StableFindingID is derived from machine-semantic context and packet
// references, never Go map iteration or localized presentation strings.
// It must only be called with source packet references established by the
// capture reader; this helper does not invent evidence.
func StableFindingID(detectorID, detectorVersion, category string, refs []PacketSourceReference) (string, error) {
	// Do not permit whitespace aliases for detector or category identity.
	// Allowing both "lacp.state" and " lacp.state" would evade stable IDs.
	for _, value := range []string{detectorID, detectorVersion, category} {
		if value == "" || value != strings.TrimSpace(value) {
			return "", errors.New("finding identity has a non-canonical detector/version/category")
		}
	}
	if len(refs) == 0 {
		return "", errors.New("finding identity requires packet references")
	}
	// Serialize only machine-semantic identifiers. Human-language reasons
	// and localized presentation text must never change finding identity.
	// JSON sorts map keys; sorting the serialized references also handles
	// otherwise-equal packet IDs with different observed protocol fields.
	type sourceIdentity struct {
		CaptureID           string            `json:"capture_id"`
		PacketNumber        uint64            `json:"packet_number"`
		Timestamp           *time.Time        `json:"timestamp,omitempty"`
		CaptureSectionIndex *int              `json:"capture_section_index,omitempty"`
		CaptureInterfaceID  *int              `json:"capture_interface_id,omitempty"`
		RelevantFields      map[string]string `json:"relevant_fields,omitempty"`
	}
	canonical := make([]string, 0, len(refs))
	seenCanonical := make(map[string]struct{}, len(refs))
	// A capture's packet number identifies one immutable source packet.
	// Multiple reasons or protocol fields are permitted, but different
	// timestamp/interface provenance for the same packet is contradictory.
	type provenanceKey struct {
		captureID    string
		packetNumber uint64
	}
	seenProvenance := make(map[provenanceKey]PacketSourceReference, len(refs))
	for _, p := range refs {
		if strings.TrimSpace(p.CaptureID) == "" || p.CaptureID != strings.TrimSpace(p.CaptureID) || p.PacketNumber == 0 {
			return "", errors.New("cannot identify a packet with non-canonical capture identity")
		}
		if (p.CaptureInterfaceID == nil) != (p.CaptureSectionIndex == nil) {
			return "", errors.New("packet identity requires section and interface together")
		}
		if p.CaptureSectionIndex != nil && *p.CaptureSectionIndex < 0 ||
			p.CaptureInterfaceID != nil && *p.CaptureInterfaceID < 0 {
			return "", errors.New("packet identity contains negative section/interface")
		}
		pk := provenanceKey{captureID: p.CaptureID, packetNumber: p.PacketNumber}
		if previous, seen := seenProvenance[pk]; seen {
			if !sameOptionalInt(previous.CaptureSectionIndex, p.CaptureSectionIndex) ||
				!sameOptionalInt(previous.CaptureInterfaceID, p.CaptureInterfaceID) ||
				!sameOptionalInstant(previous.Timestamp, p.Timestamp) {
				return "", fmt.Errorf("conflicting provenance for packet %d from capture %q", p.PacketNumber, p.CaptureID)
			}
		} else {
			seenProvenance[pk] = p
		}
		// A timestamp represents an instant, not its display timezone.
		// JSON would otherwise hash equal instants differently by offset.
		var timestamp *time.Time
		if p.Timestamp != nil {
			utc := p.Timestamp.UTC()
			timestamp = &utc
		}
		src, err := json.Marshal(sourceIdentity{
			CaptureID: p.CaptureID, PacketNumber: p.PacketNumber,
			Timestamp: timestamp, CaptureSectionIndex: p.CaptureSectionIndex,
			CaptureInterfaceID: p.CaptureInterfaceID,
			RelevantFields:     p.RelevantFields,
		})
		if err != nil {
			return "", fmt.Errorf("marshal packet identity: %w", err)
		}
		key := string(src)
		if _, duplicate := seenCanonical[key]; duplicate {
			continue // repeated packet reasons are not new source evidence
		}
		seenCanonical[key] = struct{}{}
		canonical = append(canonical, key)
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
