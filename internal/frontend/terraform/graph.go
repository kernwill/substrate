package terraform

import (
	"github.com/kernwill/substrate/internal/provenance"
)

// ResourceAddress identifies a Terraform resource the way Terraform
// itself does: "type.name", e.g. "aws_s3_bucket.example". It
// deliberately does not support the indexed forms count/for_each
// produce ("type.name[0]", "type.name[\"key\"]") - see Parse's doc
// comment on why those are Unresolved rather than modeled.
type ResourceAddress struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// String renders a in Terraform's own "type.name" address form.
func (a ResourceAddress) String() string { return a.Type + "." + a.Name }

// AttributeValue is one resource attribute's parsed value: exactly one
// of Value (a statically-resolved literal) or Unresolved (a reason it
// could not be) is set, never both, never neither. Value holds the same
// shape encoding/json produces from unmarshaling arbitrary JSON - a
// string, bool, float64, []any, or map[string]any - so a resolved
// attribute serializes and deserializes without a custom type.
type AttributeValue struct {
	Value      any    `json:"value,omitempty"`
	Unresolved string `json:"unresolved,omitempty"`
}

// Reference records that one resource's attribute expression refers to
// another resource declared in the same configuration, e.g.
// "bucket = aws_s3_bucket.example.id" on
// aws_s3_bucket_versioning.example is a Reference to
// aws_s3_bucket.example's "id" attribute. This is the resource graph's
// edge (FR-2.1's "produce a resource graph"), not an evaluated value:
// an attribute like a bucket's "id" is only known after Terraform
// applies the configuration against a real provider, so recording the
// dependency relationship is the correct static fact here, not a
// guessed-at value (FR-2.3's "never guess"). A referencing attribute is
// recorded as BOTH an Unresolved AttributeValue (it has no static
// value) and a Reference (it does have a known target) - the two are
// not mutually exclusive.
type Reference struct {
	// Attribute is the name of the attribute on the referencing resource
	// whose expression is this reference (e.g. "bucket").
	Attribute string          `json:"attribute"`
	Target    ResourceAddress `json:"target"`
	// TargetAttribute is the attribute path on Target being referenced
	// (e.g. "id"), joined with "." for a multi-step path.
	TargetAttribute string `json:"target_attribute"`
}

// Resource is one parsed "resource" block, treated as a single fact
// (FR-4.1's provenance granularity is per-resource here, at the block's
// own defining location - not per-attribute; a future IR-population
// pass is free to split a Resource's Attributes into finer-grained
// facts if a mapping needs that, but this package's own job is parsing
// and collecting, not that normalization).
type Resource struct {
	Address    ResourceAddress           `json:"address"`
	Attributes map[string]AttributeValue `json:"attributes"`
	References []Reference               `json:"references,omitempty"`
	Provenance provenance.Record         `json:"provenance"`
}

// ResourceGraph is every resource parsed from one Terraform
// configuration directory, per FR-2.1.
//
// TODO(mapping): deciding how a Resource here becomes one or more
// internal/ir Nodes - which NIST 800-53 control family an
// "aws_s3_bucket_server_side_encryption_configuration" resource belongs
// to, for instance - is real architectural work this package
// deliberately does not do. internal/frontend's own contract is to
// produce raw, framework-unaware facts; internal/ir's contract is to be
// the normalized, 800-53-keyed graph. Nothing today defines which
// package, or what new one, is responsible for the mapping step between
// them, and guessing at that here - by importing internal/ir and
// picking a ControlFamily per resource type - would bake in an
// unreviewed answer to a question that affects every future collector
// (Kubernetes, GitHub Actions, cloud APIs), not just this one. Revisit
// when the next collector is built and the shape of that mapping step
// is clearer from having two real examples instead of one.
type ResourceGraph struct {
	Resources []Resource `json:"resources"`
}
