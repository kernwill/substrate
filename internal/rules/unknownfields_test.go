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

// structWithUnexportedField is a test-only fixture for
// TestJSONFieldNamesSkipsUnexportedFields: an unexported field with no
// json tag, alongside an exported tagged one.
type structWithUnexportedField struct {
	Known  string `json:"known"`
	secret string // deliberately unexported and untagged
}

// TestJSONFieldNamesSkipsUnexportedFields is a regression test for a gap
// the code review's ultra pass found: jsonFieldNames added a field's bare
// Go name to the "known fields" list whenever it had no json tag, without
// checking whether the field was actually exported (reflect.StructField's
// PkgPath == "" is the standard test). encoding/json itself never reads
// or writes unexported fields, so counting "secret" as a known JSON key
// here would be wrong: decodeWithExtra would then delete a
// same-named "secret" key from the raw object even though the struct's
// real decode never consumed it, silently losing a genuine unknown field
// with that name instead of preserving it in Extra.
func TestJSONFieldNamesSkipsUnexportedFields(t *testing.T) {
	names := jsonFieldNames(&structWithUnexportedField{})
	for _, n := range names {
		if n == "secret" {
			t.Fatalf("jsonFieldNames = %v, must not include the unexported field's name", names)
		}
	}
	if len(names) != 1 || names[0] != "known" {
		t.Errorf("jsonFieldNames = %v, want [\"known\"]", names)
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
