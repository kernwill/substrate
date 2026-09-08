// Package ir defines the framework-agnostic evidence graph.
//
// This package is the moat. Everything else is replaceable.
//
// CONTRACT:
//   - Keyed on NIST 800-53 control families. Framework-specific vocabulary is
//     forbidden here; see scripts/check-boundaries.sh for the enforced list.
//   - MUST NOT import internal/backends or internal/frontend.
//   - Serialization is stable and byte-reproducible: sorted keys, no wall-clock
//     time in output, no map iteration order dependence.
//   - Schema is versioned. Old artifacts must remain readable.
package ir
