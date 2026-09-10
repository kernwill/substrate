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
//   - Nodes store measurements, never verdicts (FR-5.9): a node holds the
//     raw collected fact (an integer, a string, a boolean flag about
//     infrastructure state), never a framework's pass/fail predicate over
//     it. Asserting a threshold or predicate against a measurement is
//     backend mapping logic (FR-6), which this package deliberately does
//     not implement.
//   - A control's evidence may be split across a derivable Node and a
//     non-derivable Attestation (FR-5.8); this package never collapses a
//     control into one boolean or one status enum - that judgment, like
//     the predicate evaluation above, belongs to a backend.
package ir
