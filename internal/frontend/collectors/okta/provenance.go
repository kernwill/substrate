package okta

import (
	"time"

	"github.com/kernwill/substrate/internal/provenance"
	"github.com/kernwill/substrate/internal/redact"
)

// observedRecord and unresolvedRecord mirror aws's package-level
// helpers of the same name (internal/frontend/collectors/aws/provenance.go)
// exactly, with SourceType "okta" instead of "aws" - every collector in
// this package builds its Provenance.Record through these two
// functions rather than each growing its own copy of the same shape.
func observedRecord(collectorVersion, api string, params map[string]string, observedAt time.Time) provenance.Record {
	return provenance.Record{
		SourceType:       "okta",
		Locator:          provenance.Locator{API: api, Parameters: params},
		Timestamp:        observedAt,
		CollectorVersion: collectorVersion,
		Basis:            provenance.Observed,
		Confidence:       provenance.Deterministic,
	}
}

// unresolvedRecord's reason is redacted (CLAUDE.md's "redact at
// collection") since every call site builds it from a raw parsing or
// HTTP error - see aws.unresolvedRecord's doc comment for the same
// defense-in-depth reasoning applied here.
func unresolvedRecord(collectorVersion, api, reason string, params map[string]string, observedAt time.Time) provenance.Record {
	r := observedRecord(collectorVersion, api, params, observedAt)
	r.Confidence = provenance.Unresolved
	r.UnresolvedReason = redact.String(reason)
	return r
}
