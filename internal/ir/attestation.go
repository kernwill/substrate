package ir

import (
	"fmt"

	"github.com/kernwill/substrate/internal/provenance"
)

// AttestationID uniquely identifies an Attestation within a Graph. Like
// NodeID, generating stable IDs is a frontend/collector concern; this
// package treats it as an opaque, caller-supplied string.
type AttestationID string

// Attestation records a human's testimony that some portion of a control
// was carried out, for the portion of a control that no collector can
// ever observe or derive from infrastructure (FR-5.8).
//
// The crosswalk analysis that drove this requirement found controls
// where one 800-53 control splits cleanly into a mechanically-derivable
// part and a purely procedural part - the worked example is
// cryptographic key management: automated rotation and policy is a
// Node like any other, but some frameworks additionally require a
// manual, dual-control key ceremony performed by two named humans and
// recorded on a signed form. Nothing in Terraform, Kubernetes, CI
// config, or a cloud API can ever produce that fact. Silence - no Node
// for that control - would be indistinguishable from "we never checked,"
// which is exactly the "absence of evidence is not evidence of
// compliance" failure this project is built to avoid.
//
// An Attestation is deliberately not a Node: it does not carry a
// Kind/Attributes measurement, because there is no measurement to make -
// see Node's doc comment on FR-5.9. It exists to let a control's
// evidence be split (FR-5.8) across a derivable Node and a
// non-derivable Attestation without forcing either one to stand in for
// the whole control, and without the IR itself ever computing or
// storing a verdict about whether the control, as a whole, is
// satisfied - that judgment belongs entirely to a backend's mapping
// logic (FR-6), which this skeleton deliberately does not implement.
type Attestation struct {
	ID            AttestationID `json:"id"`
	ControlFamily ControlFamily `json:"control_family"`
	// Controls enumerates the specific control(s) or enhancement(s) this
	// attestation covers, mirroring Node.Controls. Omitted (not just
	// empty) when only the family is known.
	Controls []Control `json:"controls,omitempty"`
	// Statement is what was attested to, in the attester's or collector's
	// own words (e.g. "split-knowledge, dual-control ceremony performed
	// for the production signing key per documented procedure"). Free-form
	// like Node.Kind, for the same reason: what an attestation actually
	// says varies by control and isn't this skeleton's concern.
	Statement string `json:"statement"`
	// Attester identifies who attested - a name, role, or other stable
	// identifier the frontend collector considers sufficient. Required:
	// an attestation with no recorded attester is exactly the kind of
	// unattributable claim this type exists to rule out.
	Attester string `json:"attester"`
	// Provenance's Timestamp is the date attested (when the underlying
	// ceremony or procedure took place, per Provenance.Timestamp's own
	// "when the fact was true at the source" meaning), not necessarily
	// when a collector later read the signed record into this graph.
	Provenance provenance.Record `json:"provenance"`
	// SchemaVersion pins this record to a specific version of this
	// package's own JSON shape (FR-5.4); see Node.SchemaVersion for why
	// it's per-record rather than per-file.
	SchemaVersion string `json:"schema_version"`
}

// Validate checks a's own internal consistency: required fields are
// present, its Provenance is itself valid, and Provenance.Basis is
// Declared. Basis is constrained to Declared (never Observed) because an
// attestation is definitionally someone's declared testimony - nothing
// observes a human ceremony via a live API call, so an Observed
// Attestation would be a modeling mistake, not a legitimate fact.
func (a Attestation) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("ir: attestation: id is required")
	}
	if a.ControlFamily == "" {
		return fmt.Errorf("ir: attestation %s: control_family is required", a.ID)
	}
	if a.Statement == "" {
		return fmt.Errorf("ir: attestation %s: statement is required", a.ID)
	}
	if a.Attester == "" {
		return fmt.Errorf("ir: attestation %s: attester is required", a.ID)
	}
	if a.SchemaVersion == "" {
		return fmt.Errorf("ir: attestation %s: schema_version is required", a.ID)
	}
	if err := a.Provenance.Validate(); err != nil {
		return fmt.Errorf("ir: attestation %s: %w", a.ID, err)
	}
	if a.Provenance.Basis != provenance.Declared {
		return fmt.Errorf("ir: attestation %s: provenance basis is %q, must be %q", a.ID, a.Provenance.Basis, provenance.Declared)
	}
	for i, c := range a.Controls {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("ir: attestation %s: control %d: %w", a.ID, i, err)
		}
		if c.Family != a.ControlFamily {
			return fmt.Errorf("ir: attestation %s: control %d has family %q, want %q (must match control_family)", a.ID, i, c.Family, a.ControlFamily)
		}
	}
	return nil
}
