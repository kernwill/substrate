// Package kubernetes parses plain Kubernetes manifests into a resource
// graph (FR-2.4, FR-2.5).
//
// CONTRACT (per internal/frontend's own contract, which this package
// inherits):
//   - Produces raw facts, with full provenance, tagged Declared.
//   - Knows nothing about any compliance framework or NIST 800-53
//     control family - see internal/frontend/terraform's graph.go for
//     the shared TODO(mapping) this package inherits too.
//
// Unlike internal/frontend/terraform, a plain manifest has no
// expression language: every field is already a literal YAML value by
// the time it reaches this package, so there is no AttributeValue /
// Unresolved concept here (compare graph.go's Resource.Attributes,
// which is a plain map[string]any). FR-2.5's "extract network policies,
// RBAC bindings, pod security context, secret references, admission
// config" is satisfied by parsing each object faithfully into the graph
// - a NetworkPolicy's spec, a Deployment's pod securityContext, and so
// on are all just nested content under Attributes, the same way
// Terraform's nested HCL blocks are - not by this package special-casing
// any particular Kind. Scoping this package to Kind-agnostic parsing
// keeps it genuinely framework- and resource-type-unaware, matching
// internal/frontend's own contract, and matches how the vendored
// testdata/fixtures/minimal/k8s/deployment.yaml fixture (a Deployment's
// pod security context, and a NetworkPolicy) is covered without any
// Kind-specific code.
//
// Scope, deliberately narrower than FR-2.4's full text: Helm rendering
// ("render Helm with supplied values") is not implemented. No fixture
// or design partner input exercises a chart yet, and rendering one is a
// substantial feature of its own (a template engine, sprig functions,
// values.yaml layering, chart dependency resolution) - the same
// reasoning internal/frontend/terraform's module-expansion deferral
// documents. A file that isn't a plain, literal Kubernetes manifest
// (Helm template syntax included) fails Parse loudly rather than being
// silently skipped or guessed at.
//
// Cross-object references RBAC bindings and secret mounts would need
// (a RoleBinding's roleRef and subjects, a pod's
// volumes[].secret.secretName) are not modeled as graph edges yet - no
// fixture exercises them today (the vendored fixture has neither),
// unlike internal/frontend/terraform's reference detection, which the
// fixture does exercise. This is a real gap in FR-2.5's stated scope
// ("RBAC bindings," "secret references"), recorded here rather than
// guessed at with an unexercised implementation; revisit when a fixture
// needs it.
package kubernetes
