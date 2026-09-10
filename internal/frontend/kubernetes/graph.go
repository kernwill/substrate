package kubernetes

import (
	"fmt"

	"github.com/kernwill/substrate/internal/provenance"
)

// ResourceAddress identifies a Kubernetes object the way the API server
// itself does: apiVersion, kind, and name, plus namespace for
// namespace-scoped objects (empty for cluster-scoped ones, e.g. a
// ClusterRole).
type ResourceAddress struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
}

// String renders a as Kubernetes tooling conventionally does:
// "kind.name" for a cluster-scoped object, "kind.namespace/name" for a
// namespaced one. apiVersion is omitted (unlike ResourceAddress's own
// fields) because it rarely disambiguates in practice within one
// manifest set and every real conflict already surfaces through
// Parse's duplicate-address check, which does compare it.
func (a ResourceAddress) String() string {
	if a.Namespace == "" {
		return fmt.Sprintf("%s.%s", a.Kind, a.Name)
	}
	return fmt.Sprintf("%s.%s/%s", a.Kind, a.Namespace, a.Name)
}

// Resource is one parsed Kubernetes object - one YAML document - treated
// as a single fact (FR-4.1's provenance granularity is per-object here,
// at the document's own starting line in its file, not per-field).
// Attributes holds the object's full decoded content (apiVersion, kind,
// metadata, spec, and anything else present) verbatim, not just the
// fields not already lifted into Address - keeping the fact
// self-describing without needing to cross-reference Address to
// reconstruct what was actually in the manifest.
type Resource struct {
	Address    ResourceAddress   `json:"address"`
	Attributes map[string]any    `json:"attributes"`
	Provenance provenance.Record `json:"provenance"`
}

// ResourceGraph is every object parsed from one Kubernetes manifest
// directory, per FR-2.4/FR-2.5.
type ResourceGraph struct {
	Resources []Resource `json:"resources"`
}
