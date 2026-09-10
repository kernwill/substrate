package ir

import (
	"testing"

	"github.com/kernwill/substrate/internal/provenance"
)

func validAttestation(id AttestationID) Attestation {
	return Attestation{
		ID:            id,
		ControlFamily: "SC",
		Controls:      []Control{{Family: "SC", Base: 12}},
		Statement:     "split-knowledge, dual-control key ceremony performed for the production signing key per documented procedure",
		Attester:      "Jane Doe, Security Officer",
		Provenance:    validProvenance(),
		SchemaVersion: SchemaVersion,
	}
}

func TestAttestationValidateAcceptsWellFormedAttestation(t *testing.T) {
	if err := validAttestation("a1").Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestAttestationValidateRejectsMissingID(t *testing.T) {
	a := validAttestation("a1")
	a.ID = ""
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing id")
	}
}

func TestAttestationValidateRejectsMissingControlFamily(t *testing.T) {
	a := validAttestation("a1")
	a.ControlFamily = ""
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing control_family")
	}
}

func TestAttestationValidateRejectsMissingStatement(t *testing.T) {
	a := validAttestation("a1")
	a.Statement = ""
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing statement")
	}
}

func TestAttestationValidateRejectsMissingAttester(t *testing.T) {
	a := validAttestation("a1")
	a.Attester = ""
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing attester")
	}
}

func TestAttestationValidateRejectsMissingSchemaVersion(t *testing.T) {
	a := validAttestation("a1")
	a.SchemaVersion = ""
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for missing schema_version")
	}
}

func TestAttestationValidatePropagatesInvalidProvenance(t *testing.T) {
	a := validAttestation("a1")
	a.Provenance.SourceType = ""
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error propagated from an invalid Provenance")
	}
}

// TestAttestationValidateRejectsObservedBasis backs Attestation's own
// invariant: a human attestation is definitionally Declared testimony,
// never something a live API call Observes.
func TestAttestationValidateRejectsObservedBasis(t *testing.T) {
	a := validAttestation("a1")
	a.Provenance.Basis = provenance.Observed
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for an Observed attestation")
	}
}

func TestAttestationValidateRejectsControlFamilyMismatch(t *testing.T) {
	a := validAttestation("a1")
	a.Controls = []Control{{Family: "AC", Base: 6}}
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error for a control whose family does not match control_family")
	}
}

func TestAttestationValidatePropagatesInvalidControl(t *testing.T) {
	a := validAttestation("a1")
	a.Controls = []Control{{Family: "SC", Base: 0}}
	if err := a.Validate(); err == nil {
		t.Error("Validate() = nil, want error propagated from an invalid Control")
	}
}
