package ir

import (
	"fmt"

	"github.com/kernwill/substrate/internal/provenance"
)

// Edge is one relationship between two Nodes in the evidence graph
// (FR-5.1). Like Node.Kind, Relationship is a free-form label - what
// relationship types actually exist (e.g. "attached_to", "authorizes",
// "supersedes") is mapping-layer work, not part of this skeleton.
//
// An edge carries its own Provenance because a relationship is itself
// an assertion someone collected evidence for (e.g. "this security
// group is attached to this instance" was read from a specific
// Terraform attribute, or observed via a specific API call), not free
// metadata about two already-proven nodes.
type Edge struct {
	From         NodeID            `json:"from"`
	To           NodeID            `json:"to"`
	Relationship string            `json:"relationship"`
	Provenance   provenance.Record `json:"provenance"`
	// SchemaVersion pins this record to a specific version of this
	// package's own JSON shape (FR-5.4); see Node.SchemaVersion for why
	// it's per-record rather than per-file.
	SchemaVersion string `json:"schema_version"`
}

// Validate checks e's own internal consistency: required fields are
// present, and its Provenance is itself valid.
func (e Edge) Validate() error {
	if e.From == "" {
		return fmt.Errorf("ir: edge: from is required")
	}
	if e.To == "" {
		return fmt.Errorf("ir: edge %s->%s: to is required", e.From, e.To)
	}
	if e.Relationship == "" {
		return fmt.Errorf("ir: edge %s->%s: relationship is required", e.From, e.To)
	}
	if e.SchemaVersion == "" {
		return fmt.Errorf("ir: edge %s->%s: schema_version is required", e.From, e.To)
	}
	if err := e.Provenance.Validate(); err != nil {
		return fmt.Errorf("ir: edge %s->%s: %w", e.From, e.To, err)
	}
	return nil
}
