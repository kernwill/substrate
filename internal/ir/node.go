package ir

import (
	"fmt"

	"github.com/kernwill/substrate/internal/provenance"
)

// NodeID uniquely identifies a Node within a Graph. Generating stable,
// meaningful IDs is a frontend/collector concern (mapping logic, not
// data model), so this package treats a NodeID as an opaque, caller-supplied string.
type NodeID string

// Node is one fact in the evidence graph (FR-5.1). It is keyed to a
// NIST 800-53 control family (FR-5.2) - the coarse classification that
// should always be determinable - with an optional list of specific
// controls when the mapping is unambiguous enough to enumerate them
// exactly.
//
// Kind and Attributes are deliberately generic: what a fact actually
// contains (an S3 bucket's encryption setting, a pod's security
// context, a workflow's required reviewers) varies enormously across
// front-end sources and isn't defined by this skeleton - that's FR-2/
// FR-3 collector work. Kind is a free-form label for what sort of fact
// this is; Attributes is its collected data as a flat string map.
type Node struct {
	ID            NodeID        `json:"id"`
	ControlFamily ControlFamily `json:"control_family"`
	// Controls enumerates specific controls or enhancements within
	// ControlFamily when that's unambiguous (FR-5.2's "enumerated where
	// unambiguous"). Omitted (not just empty) when only the family is known.
	Controls   []Control         `json:"controls,omitempty"`
	Kind       string            `json:"kind"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provenance provenance.Record `json:"provenance"`
	// SchemaVersion pins this record to a specific version of this
	// package's own JSON shape (FR-5.4), independent of any framework
	// dataset's own version. Recorded per-record, not once per file, so
	// each JSON Lines line stays independently interpretable if files
	// are ever split, concatenated, or streamed.
	SchemaVersion string `json:"schema_version"`
}

// Validate checks n's own internal consistency: required fields are
// present, and its Provenance is itself valid. It does not check
// against any actual dataset or source - only that n is well-formed
// enough to belong in a Graph.
func (n Node) Validate() error {
	if n.ID == "" {
		return fmt.Errorf("ir: node: id is required")
	}
	if n.ControlFamily == "" {
		return fmt.Errorf("ir: node %s: control_family is required", n.ID)
	}
	if n.Kind == "" {
		return fmt.Errorf("ir: node %s: kind is required", n.ID)
	}
	if n.SchemaVersion == "" {
		return fmt.Errorf("ir: node %s: schema_version is required", n.ID)
	}
	if err := n.Provenance.Validate(); err != nil {
		return fmt.Errorf("ir: node %s: %w", n.ID, err)
	}
	for i, c := range n.Controls {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("ir: node %s: control %d: %w", n.ID, i, err)
		}
		if c.Family != n.ControlFamily {
			return fmt.Errorf("ir: node %s: control %d has family %q, want %q (must match control_family)", n.ID, i, c.Family, n.ControlFamily)
		}
	}
	return nil
}
