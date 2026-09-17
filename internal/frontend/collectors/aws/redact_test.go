package aws

import (
	"testing"

	"github.com/kernwill/substrate/internal/redact"
)

// TestUnresolvedRecordRedactsReason confirms unresolvedRecord (the one
// choke point every collector in this package routes a failed API
// call's error text through - see provenance.go) redacts that text
// before it reaches Provenance.UnresolvedReason. AWS API errors aren't
// documented to ever echo customer secrets, but this is the one place
// arbitrary, uncontrolled text reaches a provenance.Record at all in
// this package, and the defense-in-depth pass over it is cheap.
func TestUnresolvedRecordRedactsReason(t *testing.T) {
	reason := "request failed: AKIAIOSFODNN7EXAMPLE was used to sign the request"
	r := unresolvedRecord("test/v0", "test:API", reason, map[string]string{"k": "v"}, testObservedAt)
	if r.UnresolvedReason == reason {
		t.Fatal("UnresolvedReason was not redacted")
	}
	if r.UnresolvedReason != redact.String(reason) {
		t.Errorf("UnresolvedReason = %q, want %q", r.UnresolvedReason, redact.String(reason))
	}
}
