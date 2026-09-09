package rules

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestMarshalJSONDoesNotHTMLEscape backs marshalJSON's core claim.
func TestMarshalJSONDoesNotHTMLEscape(t *testing.T) {
	b, err := marshalJSON(map[string]string{"s": "a > b & c < d"})
	if err != nil {
		t.Fatalf("marshalJSON: %v", err)
	}
	if got, want := string(b), `{"s":"a > b & c < d"}`; got != want {
		t.Errorf("marshalJSON = %s, want %s", got, want)
	}
}

// TestMarshalJSONAloneIsNotEnough backs the other half of marshalJSON's
// doc comment: fixing the per-type marshaler alone does not make a
// plain top-level json.Marshal call escape-free, because Go's json
// package re-applies HTML-escaping to a nested json.Marshaler's
// returned bytes based on the OUTERMOST call's own setting. This test
// exists to keep that documented claim honest - if a future Go version
// changed this behavior, every caller that relies on an outer
// escape-disabled json.Encoder (cmd/substrate/rulesdiff.go, this
// package's own diffRecords) would need re-auditing.
func TestMarshalJSONAloneIsNotEnough(t *testing.T) {
	rule := FRRRequirement{Name: "x", Statement: "a > b", Force: ForceMust, Affects: []AffectedParty{AffectsProviders}}

	b, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.ContainsRune(b, '>') {
		t.Fatalf("expected a plain top-level json.Marshal to HTML-escape the literal '>' away; if this now fails, marshalJSON's doc comment is stale and should be updated. Got: %s", b)
	}
	escaped := []byte{'\\', 'u', '0', '0', '3', 'e'} // the literal 6-byte sequence `>`
	if !bytes.Contains(b, escaped) {
		t.Fatalf(`expected json.Marshal output to contain the HTML-escaped form of '>' (>), got: %s`, b)
	}
}
