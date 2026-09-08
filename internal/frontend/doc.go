// Package frontend parses and collects facts from a customer's sources of truth.
//
// CONTRACT:
//   - Produces raw facts. Knows nothing about any compliance framework.
//   - MUST NOT import internal/backends.
//   - Every emitted fact carries full provenance (source, locator, timestamp,
//     collector version) and is tagged Declared or Observed.
//   - Never infers. If a value cannot be resolved, emit Unresolved with a reason.
package frontend
