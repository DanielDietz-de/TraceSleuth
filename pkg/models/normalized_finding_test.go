package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validAlphaFinding(t *testing.T) DiagnosticFinding {
	t.Helper()
	first := time.Unix(1_000, 0).UTC()
	last := first.Add(300 * time.Millisecond)
	iface := 0 // Interface ID zero is valid and must not be omitted.
	packet := PacketSourceReference{
		CaptureID: "sha256:capture-a", PacketNumber: 1289,
		Timestamp: &first, CaptureInterfaceID: &iface,
		Reason: "LACP partner changed", RelevantFields: map[string]string{
			"lacp.partner_system_id": "00:11:22:33:44:55",
		},
	}
	id, err := StableFindingID("lacp.partner_instability", "1.0", "redundancy", []PacketSourceReference{packet})
	if err != nil {
		t.Fatal(err)
	}
	return DiagnosticFinding{
		ID: id, DetectorID: "lacp.partner_instability",
		DetectorVersion: "1.0", SchemaVersion: NormalizedFindingSchemaVersion,
		Title:    "LACP partner system identity changed",
		Summary:  "A directly decoded partner field changed during the observed interval.",
		Category: "redundancy", Severity: SeverityMedium, Certainty: CertaintyProbable,
		Confidence: ExplainedConfidence{
			Base: 50,
			Adjustments: []ConfidenceAdjustment{
				{EvidenceFamily: "direct_lacp_state", Delta: 25, Reason: "Decoded partner ID change", EvidenceIDs: []string{"evidence-1"}},
				{EvidenceFamily: "capture_visibility", Delta: -10, Reason: "Only one capture interface was visible", EvidenceIDs: []string{"evidence-2"}},
			},
			Final: 65,
		},
		FirstSeen: &first, LastSeen: &last,
		PacketReferences: []PacketSourceReference{packet},
		Evidence: []FindingEvidence{
			{ID: "evidence-1", Kind: "packet", Description: "New partner identity", Packet: &packet},
			{ID: "evidence-2", Kind: "capture_quality", Description: "Single-sided capture"},
		},
		AlternativeExplanations: []string{"Capture duplication or monitor port reconfiguration"},
		CaptureLimitations:      []string{"Capture observes only one side of the link"},
		WiresharkFilters:        []string{"eth.type == 0x8809"},
		RecommendedValidation:   []string{"Inspect packet 1289 in the original capture with Wireshark"},
	}
}

func TestNormalizedFindingValidatesEvidenceAndUncertainty(t *testing.T) {
	f := validAlphaFinding(t)
	if err := f.Validate(); err != nil {
		t.Fatalf("valid normalized finding rejected: %v", err)
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"schema_version", "packet_references", "capture_interface_id",
		"alternative_explanations", "capture_limitations",
		"wireshark_filters", "recommended_validation",
	} {
		if !strings.Contains(string(data), `"`+key+`"`) {
			t.Errorf("normalized JSON missing %s: %s", key, data)
		}
	}
	if strings.Contains(string(data), "packet_payload") {
		t.Fatal("finding leaked a packet payload field")
	}
}

func TestNormalizedFindingValidationRejectsUnverifiableClaims(t *testing.T) {
	base := validAlphaFinding(t)
	for _, tc := range []struct {
		name string
		edit func(*DiagnosticFinding)
	}{
		{"missing provenance", func(f *DiagnosticFinding) { f.PacketReferences = nil }},
		{"missing Wireshark validation", func(f *DiagnosticFinding) { f.WiresharkFilters = nil }},
		{"missing alternatives", func(f *DiagnosticFinding) { f.AlternativeExplanations = nil }},
		{"missing time", func(f *DiagnosticFinding) { f.FirstSeen = nil }},
		{"wrong order", func(f *DiagnosticFinding) {
			earlier := f.FirstSeen.Add(-time.Second)
			f.LastSeen = &earlier
		}},
		{"unknown schema", func(f *DiagnosticFinding) { f.SchemaVersion = "unknown" }},
		{"unknown severity", func(f *DiagnosticFinding) { f.Severity = "panic" }},
		{"wrong confidence", func(f *DiagnosticFinding) { f.Confidence.Final = 95 }},
		{"unknown evidence", func(f *DiagnosticFinding) {
			f.Confidence.Adjustments[0].EvidenceIDs = []string{"not-a-real-packet"}
		}},
		{"duplicate evidence ID", func(f *DiagnosticFinding) { f.Evidence[1].ID = f.Evidence[0].ID }},
		{"no source packet number", func(f *DiagnosticFinding) { f.PacketReferences[0].PacketNumber = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone := base
			clone.PacketReferences = append([]PacketSourceReference(nil), base.PacketReferences...)
			clone.Evidence = append([]FindingEvidence(nil), base.Evidence...)
			clone.Confidence.Adjustments = append([]ConfidenceAdjustment(nil), base.Confidence.Adjustments...)
			tc.edit(&clone)
			if err := clone.Validate(); err == nil {
				t.Fatalf("%s unexpectedly passed strict finding validation", tc.name)
			}
		})
	}
}

func TestNormalizedConfidenceClampsAndRejectsCorrelatedEvidence(t *testing.T) {
	for _, tc := range []struct {
		base, delta, expected int
	}{
		{95, 25, 100}, {5, -20, 0}, {25, 30, 55},
	} {
		conf := ExplainedConfidence{Base: tc.base, Adjustments: []ConfidenceAdjustment{{
			EvidenceFamily: "documented-source", Delta: tc.delta, Reason: "fixture-derived evidence",
		}}}
		got, err := conf.Calculated()
		if err != nil || got != tc.expected {
			t.Fatalf("confidence calculation got %d, error %v; want %d", got, err, tc.expected)
		}
	}
	conf := ExplainedConfidence{Base: 50, Adjustments: []ConfidenceAdjustment{
		{EvidenceFamily: "same-packets", Delta: 25, Reason: "duplicate frames"},
		{EvidenceFamily: "same-packets", Delta: 25, Reason: "same frames as another metric"},
	}}
	if _, err := conf.Calculated(); err == nil {
		t.Fatal("duplicate evidence family inflated confidence")
	}
	for _, invalidBase := range []int{-1, 101} {
		conf.Base = invalidBase
		if _, err := conf.Calculated(); err == nil {
			t.Fatalf("invalid confidence base %d accepted", invalidBase)
		}
	}
}

func TestStableFindingIDIndependentOfInputOrderAndMapIteration(t *testing.T) {
	packets := []PacketSourceReference{
		{CaptureID: "capture-b", PacketNumber: 2, Reason: "state change",
			RelevantFields: map[string]string{"z": "z", "a": "a"}},
		{CaptureID: "capture-a", PacketNumber: 1, Reason: "first packet",
			RelevantFields: map[string]string{"m": "m", "b": "b"}},
	}
	reversed := []PacketSourceReference{
		{CaptureID: "capture-a", PacketNumber: 1, Reason: "first packet",
			RelevantFields: map[string]string{"b": "b", "m": "m"}},
		{CaptureID: "capture-b", PacketNumber: 2, Reason: "state change",
			RelevantFields: map[string]string{"a": "a", "z": "z"}},
	}
	id1, err := StableFindingID("stp.root_change", "1", "stp", packets)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := StableFindingID("stp.root_change", "1", "stp", reversed)
	if err != nil || id1 != id2 {
		t.Fatalf("finding ID depends on packet or Go map order: %s vs %s (%v)", id1, id2, err)
	}
	reversed[0].PacketNumber++
	id3, err := StableFindingID("stp.root_change", "1", "stp", reversed)
	if err != nil || id3 == id1 {
		t.Fatalf("packet provenance changed without changing finding ID: %v", err)
	}
	if _, err := StableFindingID("", "1", "stp", packets); err == nil {
		t.Fatal("empty detector ID accepted")
	}
}
