package aws

import (
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

// observedRecord builds a Confidence=Deterministic provenance.Record for
// one successfully resolved Observed AWS API call, shared by every
// collector in this package - s3.go and iam.go each grew their own copy
// of this exact shape before this file existed, which is exactly the
// duplicated-literal risk internal/frontend/controls exists to prevent
// for control assignments; the same principle applies here at the
// provenance-construction level, so a future required Record field only
// needs to be threaded through this one function.
func observedRecord(collectorVersion, api string, params map[string]string, observedAt time.Time) provenance.Record {
	return provenance.Record{
		SourceType:       "aws",
		Locator:          provenance.Locator{API: api, Parameters: params},
		Timestamp:        observedAt,
		CollectorVersion: collectorVersion,
		Basis:            provenance.Observed,
		Confidence:       provenance.Deterministic,
	}
}

// unresolvedRecord is observedRecord's Confidence=Unresolved counterpart,
// for when api genuinely could not be answered.
func unresolvedRecord(collectorVersion, api, reason string, params map[string]string, observedAt time.Time) provenance.Record {
	r := observedRecord(collectorVersion, api, params, observedAt)
	r.Confidence = provenance.Unresolved
	r.UnresolvedReason = reason
	return r
}
