// Package provenance records the derivation chain for every fact.
//
// If we cannot show an assessor how a fact was derived, the fact is worthless.
// Provenance is not metadata, it is the product.
package provenance

import (
	"fmt"
	"time"
)

// SourceType names what kind of source a fact was collected from - a
// Terraform file, a Kubernetes manifest, a live AWS API call, and so
// on. Specific values are defined by the frontend collectors that
// produce them (FR-2/FR-3), not by this package: provenance only
// defines the shape a source type is recorded in, not the vocabulary of
// sources this project happens to support today.
type SourceType string

// Locator pinpoints exactly where a fact came from (FR-4.1): a file and
// line for a statically-collected fact, or an API name and the
// parameters used to call it for a live one. Populate exactly one pair -
// Path (with optional Line), or API (with optional Parameters) - never
// both; Record.Validate rejects a Locator that sets neither or both.
// Which pair is appropriate for a given SourceType is a convention for
// collectors to follow, not something this type enforces: SourceType is
// intentionally open-ended (see its own doc comment), so there's no
// fixed static-vs-live classification of source type strings for this
// package to check against.
type Locator struct {
	Path string `json:"path,omitempty"`
	// Line is 1-indexed, matching how editors and diff tools report
	// line numbers. Zero means "the whole file," not "line zero."
	Line int `json:"line,omitempty"`

	API        string            `json:"api,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// Basis says whether a fact reflects declared configuration (what the
// customer's source of truth says should be true) or observed runtime
// state (what a live check found to actually be true). This is a
// first-class field, not an afterthought: the target certification
// regime separates evidence of implementation from evidence of
// effectiveness and requires both (FR-4.2).
type Basis string

const (
	Declared Basis = "declared"
	Observed Basis = "observed"
)

// Confidence is how sure the collector is about a fact (FR-4.3).
// Unresolved must never collapse into Deterministic or Heuristic:
// absence of evidence is not evidence of compliance, and a fact this
// package can't stand behind must say so rather than be guessed at.
type Confidence string

const (
	// Deterministic facts were read directly from a source with no
	// interpretation involved (a Terraform attribute's literal value,
	// an API response field).
	Deterministic Confidence = "deterministic"
	// Heuristic facts required inference beyond a direct read (e.g.
	// resolving a value through a variable or module default that
	// could not be fully statically evaluated).
	Heuristic Confidence = "heuristic"
	// Unresolved facts could not be determined at all. Record carries
	// UnresolvedReason explaining why, per FR-2.3's "emit unresolved
	// with a reason. Never guess."
	Unresolved Confidence = "unresolved"
)

// Record is the full provenance of one fact: where it came from, when,
// by what, whether it's declared or observed, and how confident the
// collector is (FR-4.1 through FR-4.3). Every fact this project ever
// asserts - in internal/frontend's raw output and internal/ir's
// evidence graph alike - carries one of these, which is what makes
// FR-4.6 ("full derivation chain queryable for any assertion") possible
// at all.
type Record struct {
	SourceType SourceType `json:"source_type"`
	Locator    Locator    `json:"locator"`
	// Timestamp is when the fact was true at the source (a file's last
	// commit, an API response's observation time) - a property of the
	// collected data, not of when the compiler happened to run. This
	// package's own reproducibility contract ("no wall-clock time in
	// output") is about the compiler never injecting time.Now() into an
	// artifact; a fact's own timestamp is data, and recompiling the same
	// input at a different real moment must still produce this same
	// value. Always UTC, so two collectors in different time zones
	// produce byte-identical output for the same underlying instant.
	Timestamp time.Time `json:"timestamp"`
	// CollectorVersion is the version of the code that produced this
	// fact, so a later re-collection with a fixed or changed collector
	// can be told apart from the source itself having changed.
	CollectorVersion string     `json:"collector_version"`
	Basis            Basis      `json:"basis"`
	Confidence       Confidence `json:"confidence"`
	// UnresolvedReason explains why Confidence is Unresolved. Required
	// (and only meaningful) when Confidence == Unresolved.
	UnresolvedReason string `json:"unresolved_reason,omitempty"`
}

// Validate checks r's own internal consistency: every field FR-4.1
// requires is present, Basis and Confidence are one of their defined
// values, and UnresolvedReason is set if and only if Confidence is
// Unresolved. It does not - and cannot - check that r accurately
// describes how a fact was actually derived; that correctness is the
// collector's responsibility. Validate exists so a malformed Record
// fails loudly at the point it's constructed, rather than silently
// becoming an unusable or misleading entry in the evidence graph.
func (r Record) Validate() error {
	if r.SourceType == "" {
		return fmt.Errorf("provenance: source_type is required")
	}
	if r.Locator.Path == "" && r.Locator.API == "" {
		return fmt.Errorf("provenance: locator must set path or api")
	}
	if r.Locator.Path != "" && r.Locator.API != "" {
		return fmt.Errorf("provenance: locator sets both path and api - exactly one pair, per FR-4.1's file-and-line OR api-and-parameters")
	}
	if r.Timestamp.IsZero() {
		return fmt.Errorf("provenance: timestamp is required")
	}
	if r.CollectorVersion == "" {
		return fmt.Errorf("provenance: collector_version is required")
	}
	switch r.Basis {
	case Declared, Observed:
	default:
		return fmt.Errorf("provenance: invalid basis %q (want %q or %q)", r.Basis, Declared, Observed)
	}
	switch r.Confidence {
	case Deterministic, Heuristic:
		if r.UnresolvedReason != "" {
			return fmt.Errorf("provenance: unresolved_reason set on a %s fact (only valid when confidence is %q)", r.Confidence, Unresolved)
		}
	case Unresolved:
		if r.UnresolvedReason == "" {
			return fmt.Errorf("provenance: confidence is %q but unresolved_reason is empty - never leave undetermined unexplained", Unresolved)
		}
	default:
		return fmt.Errorf("provenance: invalid confidence %q (want %q, %q, or %q)", r.Confidence, Deterministic, Heuristic, Unresolved)
	}
	return nil
}
