package ir

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

func validProvenance() provenance.Record {
	return provenance.Record{
		SourceType:       "terraform",
		Locator:          provenance.Locator{Path: "main.tf", Line: 3},
		Timestamp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CollectorVersion: "v0.1.0",
		Basis:            provenance.Declared,
		Confidence:       provenance.Deterministic,
	}
}

func validNode(id NodeID) Node {
	return Node{
		ID:            id,
		ControlFamily: "SC",
		Controls:      []Control{{Family: "SC", Base: 13}},
		Kind:          "encryption_at_rest",
		Attributes:    map[string]string{"algorithm": "aws:kms"},
		Provenance:    validProvenance(),
		SchemaVersion: SchemaVersion,
	}
}

func TestNodeValidateAcceptsWellFormedNode(t *testing.T) {
	if err := validNode("n1").Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestNodeValidateRejectsMissingID(t *testing.T) {
	n := validNode("n1")
	n.ID = ""
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing id")
	}
}

func TestNodeValidateRejectsMissingControlFamily(t *testing.T) {
	n := validNode("n1")
	n.ControlFamily = ""
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing control_family")
	}
}

func TestNodeValidateRejectsMissingKind(t *testing.T) {
	n := validNode("n1")
	n.Kind = ""
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing kind")
	}
}

func TestNodeValidateRejectsMissingSchemaVersion(t *testing.T) {
	n := validNode("n1")
	n.SchemaVersion = ""
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing schema_version")
	}
}

func TestNodeValidatePropagatesInvalidProvenance(t *testing.T) {
	n := validNode("n1")
	n.Provenance.SourceType = ""
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error propagated from an invalid Provenance")
	}
}

// TestNodeValidateRejectsControlFamilyMismatch is a regression test for a
// gap the code review's ultra pass found: Validate never checked that
// each entry in Controls actually belongs to n.ControlFamily, so a Node
// claiming ControlFamily "SC" could carry a Control for family "AC" with
// no error - silently breaking the invariant a consumer would reasonably
// assume (that Controls is always a refinement of ControlFamily, never a
// contradiction of it).
func TestNodeValidateRejectsControlFamilyMismatch(t *testing.T) {
	n := validNode("n1")
	n.Controls = []Control{{Family: "AC", Base: 6}}
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error for a control whose family does not match control_family")
	}
}

// TestNodeValidatePropagatesInvalidControl is a regression test for the
// same gap: Validate never called Control.Validate on its Controls
// entries, so a malformed Control (e.g. Base 0) passed silently.
func TestNodeValidatePropagatesInvalidControl(t *testing.T) {
	n := validNode("n1")
	n.Controls = []Control{{Family: "SC", Base: 0}}
	if err := n.Validate(); err == nil {
		t.Error("Validate() = nil, want error propagated from an invalid Control")
	}
}

func TestNodeControlsOmittedWhenAbsent(t *testing.T) {
	n := validNode("n1")
	n.Controls = nil
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := m["controls"]; ok {
		t.Error(`marshaled node has a "controls" key even though Controls is nil - FR-5.2 wants it enumerated only when unambiguous, not present-but-empty`)
	}
}
