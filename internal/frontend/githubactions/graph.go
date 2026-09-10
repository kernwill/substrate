package githubactions

import (
	"github.com/kernwill/substrate/internal/provenance"
)

// WorkflowAddress identifies one workflow file: Path is relative to the
// directory Parse was given (conventionally ".github/workflows"), Name
// is the workflow's own top-level "name:" field (empty if the workflow
// doesn't declare one - GitHub itself falls back to the file path in
// that case, which callers can do too).
type WorkflowAddress struct {
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
}

// String renders a as its file path, the one part of the address that
// is always present.
func (a WorkflowAddress) String() string { return a.Path }

// Workflow is one parsed workflow file, treated as a single fact
// (FR-4.1's provenance granularity is per-file here, matching
// internal/frontend/kubernetes's per-object granularity). Attributes
// holds the file's full decoded YAML content verbatim.
type Workflow struct {
	Address    WorkflowAddress   `json:"address"`
	Attributes map[string]any    `json:"attributes"`
	Provenance provenance.Record `json:"provenance"`
}

// WorkflowGraph is every workflow parsed from one directory, per FR-2.6.
type WorkflowGraph struct {
	Workflows []Workflow `json:"workflows"`
}
