package rules

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

const vendoredDatasetPath = "data/fedramp-consolidated-rules.json"

func readVendoredDataset(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(vendoredDatasetPath)
	if err != nil {
		t.Fatalf("read vendored dataset: %v", err)
	}
	return raw
}

func TestValidateSchemaAcceptsVendoredDataset(t *testing.T) {
	if err := ValidateSchema(readVendoredDataset(t)); err != nil {
		t.Fatalf("ValidateSchema(vendored dataset) = %v, want nil", err)
	}
}

func TestValidateSchemaRejectsInvalidJSON(t *testing.T) {
	err := ValidateSchema([]byte(`{not json`))
	if err == nil {
		t.Fatal("ValidateSchema(invalid JSON) succeeded, want error")
	}
	if _, ok := err.(*SchemaError); ok {
		t.Fatal("ValidateSchema(invalid JSON) returned a *SchemaError, want a plain JSON decode error")
	}
}

func TestValidateSchemaRejectsUnknownTopLevelField(t *testing.T) {
	raw := readVendoredDataset(t)
	// The dataset's top level is additionalProperties: false. Injecting an
	// unrecognized sibling key must fail loudly, not be silently accepted.
	mutated := strings.Replace(string(raw), `"info":`, `"unexpected_field": true, "info":`, 1)
	if mutated == string(raw) {
		t.Fatal("test setup: replacement did not match")
	}

	err := ValidateSchema([]byte(mutated))
	if err == nil {
		t.Fatal("ValidateSchema(dataset + unknown top-level field) succeeded, want error")
	}
	var schemaErr *SchemaError
	if !asSchemaError(err, &schemaErr) {
		t.Fatalf("error = %v (%T), want *SchemaError", err, err)
	}
}

func TestValidateSchemaRejectsMissingRequiredField(t *testing.T) {
	raw := readVendoredDataset(t)
	// info.version is required; removing it must fail loudly.
	mutated := strings.Replace(string(raw), `"version": "2026.07.14.01",`, ``, 1)
	if mutated == string(raw) {
		t.Fatal("test setup: replacement did not match")
	}

	err := ValidateSchema([]byte(mutated))
	if err == nil {
		t.Fatal("ValidateSchema(dataset - info.version) succeeded, want error")
	}
	var schemaErr *SchemaError
	if !asSchemaError(err, &schemaErr) {
		t.Fatalf("error = %v (%T), want *SchemaError", err, err)
	}
}

func TestValidateSchemaRejectsBadEnumValue(t *testing.T) {
	raw := readVendoredDataset(t)
	mutated := strings.Replace(string(raw), `"status": "stable",`, `"status": "on_fire",`, 1)
	if mutated == string(raw) {
		t.Fatal("test setup: replacement did not match")
	}

	err := ValidateSchema([]byte(mutated))
	if err == nil {
		t.Fatal("ValidateSchema(dataset with bad status enum) succeeded, want error")
	}
}

func TestValidateSchemaRejectsMalformedControlID(t *testing.T) {
	raw := string(readVendoredDataset(t))
	// KSI indicator "controls" entries must match ^[a-z]{2}-\d+(?:\.\d+)?$.
	mutated := strings.Replace(raw, `"cp-3",`, `"CP-3",`, 1)
	if mutated == raw {
		t.Fatal("test setup: replacement did not match")
	}

	err := ValidateSchema([]byte(mutated))
	if err == nil {
		t.Fatal("ValidateSchema(dataset with malformed control ID) succeeded, want error")
	}
}

// TestEcmaRegexpMatchStringPanicsOnEngineError is a regression test for a
// gap the code review's ultra pass found: ecmaRegexp.MatchString collapsed
// any regexp2 engine error into a plain "no match" (err == nil && matched),
// which jsonschema.Regexp's interface (MatchString(string) bool - no error
// return) can't distinguish from a genuine non-match. That silently turns
// an engine fault into a false schema validation result. This forces a
// real regexp2 error (a match timeout against a catastrophic-backtracking
// pattern) and checks MatchString panics instead of returning false.
func TestEcmaRegexpMatchStringPanicsOnEngineError(t *testing.T) {
	re, err := regexp2.Compile(`^(a+)+$`, regexp2.ECMAScript)
	if err != nil {
		t.Fatalf("regexp2.Compile: %v", err)
	}
	re.MatchTimeout = time.Nanosecond

	defer func() {
		if recover() == nil {
			t.Error("MatchString did not panic on a regexp2 engine error, want panic")
		}
	}()
	ecmaRegexp{re}.MatchString(strings.Repeat("a", 40) + "!")
}

// asSchemaError is errors.As without importing errors in every call site;
// kept trivial and local to this test file.
func asSchemaError(err error, target **SchemaError) bool {
	se, ok := err.(*SchemaError)
	if !ok {
		return false
	}
	*target = se
	return true
}
