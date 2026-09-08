// Package rules ingests the FedRAMP Consolidated Rules dataset.
//
// Source of truth: github.com/FedRAMP/rules, fedramp-consolidated-rules.json
// plus schemas/fedramp-consolidated-rules.schema.json.
//
// Read AGENTS.md in that repository before modifying this package. It states
// how the program office expects machines to consume the dataset.
//
// Requirements:
//   - Validate against the published schema. Fail loudly on drift.
//   - Pin and record the dataset version in every compiler output.
//   - Support diffing two dataset versions into structured change records.
//
// This package is intended for open source release (Apache 2.0). Keep it free
// of anything proprietary.
package rules
