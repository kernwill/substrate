// Package terraform parses Terraform HCL configuration into a resource
// graph (FR-2.1).
//
// CONTRACT (per internal/frontend's own contract, which this package
// inherits):
//   - Produces raw facts, with full provenance, tagged Declared (this is
//     static configuration, never live-observed state).
//   - Knows nothing about any compliance framework or NIST 800-53 control
//     family. Mapping a parsed resource onto the evidence graph
//     (internal/ir) is later, separate work this package does not do -
//     see the package-level TODO in graph.go for why that boundary is
//     deliberately left open rather than guessed at here.
//   - Never infers an attribute's runtime value. Where an attribute's
//     expression cannot be statically evaluated (a resource-to-resource
//     reference, an unresolvable variable, a data source, a module
//     output, an indexed or interpolated expression combining several of
//     these), the attribute is recorded as Unresolved with a reason
//     (FR-2.3), and a same-config resource-to-resource reference is
//     additionally recorded as a Reference (graph edge) rather than a
//     value - see AttributeValue and Reference in graph.go.
//
// Scope, deliberately narrower than FR-2.1's full text for this first
// pass: `module` blocks are detected but not expanded (no fixture or
// design partner input has exercised this yet, and module expansion -
// resolving a local path, a registry source, or a git source, then
// recursively parsing the result - is a substantial feature of its own).
// `data` blocks, `output` blocks, and `locals` are not modeled as
// resources; a reference to any of them shows up as Unresolved on the
// resource attribute that references it, never silently dropped.
package terraform
