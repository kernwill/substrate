package terraform

import (
	"testing"

	"github.com/kernwill/substrate/internal/redact"
)

// TestParseRedactsSecretShapedAttributeAtTopLevel is FR-4.5's own
// "testable" requirement: a hardcoded secret in a Terraform resource
// attribute must never survive Parse, since Parse's own raw output is
// written straight to disk (cmd/substrate's terraform.json) with no
// further scrubbing step downstream.
func TestParseRedactsSecretShapedAttributeAtTopLevel(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "example_thing" "example" {
  db_password = "hunter2"
  region      = "us-east-1"
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(g.Resources))
	}
	attrs := g.Resources[0].Attributes
	if got, want := attrs["db_password"].Value, redact.Placeholder; got != want {
		t.Errorf("db_password = %v, want %q", got, want)
	}
	if got, want := attrs["region"].Value, "us-east-1"; got != want {
		t.Errorf("region = %v, want %q (unrelated attribute must survive untouched)", got, want)
	}
}

// TestParseRedactsSecretShapedAttributeInsideNestedBlock confirms
// redaction reaches attributes inside a nested block (e.g.
// "versioning_configuration { ... }"), the map[string]AttributeValue
// shape evalBody produces for a single nested block - not just
// top-level resource attributes.
func TestParseRedactsSecretShapedAttributeInsideNestedBlock(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "example_thing" "example" {
  auth {
    api_key = "abc123"
    enabled = true
  }
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	nested, ok := g.Resources[0].Attributes["auth"].Value.(map[string]AttributeValue)
	if !ok {
		t.Fatalf("auth block did not resolve to a nested attribute map: %+v", g.Resources[0].Attributes["auth"])
	}
	if got := nested["api_key"].Value; got != redact.Placeholder {
		t.Errorf("auth.api_key = %v, want %q", got, redact.Placeholder)
	}
	if got := nested["enabled"].Value; got != true {
		t.Errorf("auth.enabled = %v, want true (unrelated attribute must survive untouched)", got)
	}
}

// TestParseRedactsSecretShapedContentInUnresolvedReason is a regression
// test: an earlier version of redactAttributeValue copied
// AttributeValue.Unresolved verbatim, exempting it from the content-
// pattern redaction layer every other string leaf gets. evalAttribute's
// "could not evaluate expression: %s" case embeds an hcl diagnostic's
// own Error() string - not this package's own fixed text - so it is
// not guaranteed never to echo secret-shaped source content back into
// the reason. This test forces that path directly (redactAttributeValue
// takes an AttributeValue, no need to construct a real unparseable HCL
// expression) to prove the fix without depending on hcl's own exact
// diagnostic wording.
func TestParseRedactsSecretShapedContentInUnresolvedReason(t *testing.T) {
	av := AttributeValue{Unresolved: "could not evaluate expression: token AKIAIOSFODNN7EXAMPLE was rejected"}
	got := redactAttributeValue(av)
	if got.Unresolved == av.Unresolved {
		t.Fatalf("Unresolved was not redacted: %q", got.Unresolved)
	}
	if got.Unresolved != redact.String(av.Unresolved) {
		t.Errorf("Unresolved = %q, want %q", got.Unresolved, redact.String(av.Unresolved))
	}
}

// TestParsePreservesUnresolvedReasonForSecretShapedName confirms an
// attribute whose name looks secret-shaped, but whose value was never
// resolved in the first place (an interpolation, a data source
// reference, etc.), keeps its real Unresolved reason rather than being
// overwritten with a fabricated resolved Placeholder value - there was
// nothing to redact, so nothing should claim to have been redacted.
func TestParsePreservesUnresolvedReasonForSecretShapedName(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "example_thing" "example" {
  api_key = data.example_data.thing.value
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	av := g.Resources[0].Attributes["api_key"]
	if av.Value != nil {
		t.Errorf("api_key.Value = %v, want nil (never resolved, so nothing to redact)", av.Value)
	}
	if av.Unresolved == "" {
		t.Error("api_key.Unresolved is empty, want the real reason preserved")
	}
}
