package kubernetes

import (
	"testing"

	"github.com/kernwill/substrate/internal/redact"
)

// TestParseRedactsSecretDataWholesale is FR-4.5's own "testable"
// requirement: a Secret object's data/stringData fields carry base64-
// or plaintext-encoded secret material by Kubernetes' own convention,
// regardless of what any individual key inside them is named - "data"
// itself is not a secret-shaped key name (a ConfigMap has one too, and
// that one is NOT secret), so this has to be redacted wholesale by Kind
// rather than caught by the generic key-name pass.
func TestParseRedactsSecretDataWholesale(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
data:
  password: aHVudGVyMg==
stringData:
  connection-string: postgres://user:hunter2@db:5432/app
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
	if got := attrs["data"]; got != redact.Placeholder {
		t.Errorf("data = %v, want %q (wholesale, regardless of the individual keys inside)", got, redact.Placeholder)
	}
	if got := attrs["stringData"]; got != redact.Placeholder {
		t.Errorf("stringData = %v, want %q", got, redact.Placeholder)
	}
}

// TestParseRedactsLastAppliedConfigAnnotation is a regression test:
// kubectl writes the object's full prior manifest into
// metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]
// on every apply, re-serialized as one JSON string - including a
// Secret's own base64 data, if the object was ever one. redact.Value's
// generic pass doesn't parse a string that happens to itself be JSON
// text, so an earlier version of this file left that annotation
// completely unredacted even on a Secret whose own top-level
// data/stringData fields it correctly wiped two lines above.
func TestParseRedactsLastAppliedConfigAnnotation(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: '{"apiVersion":"v1","kind":"Secret","data":{"password":"aHVudGVyMg=="}}'
data:
  password: aHVudGVyMg==
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	metadata := g.Resources[0].Attributes["metadata"].(map[string]any)
	annotations := metadata["annotations"].(map[string]any)
	got := annotations["kubectl.kubernetes.io/last-applied-configuration"]
	if got != redact.Placeholder {
		t.Errorf("last-applied-configuration annotation = %v, want %q", got, redact.Placeholder)
	}
}

// TestParseDoesNotRedactConfigMapDataByKindAlone confirms the Secret
// rule is genuinely Kind-aware and not a blanket "redact any 'data'
// field": a ConfigMap's own "data" field is ordinary, non-secret
// application configuration this tool needs to evidence, and must
// survive untouched.
func TestParseDoesNotRedactConfigMapDataByKindAlone(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  log_level: info
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	attrs := g.Resources[0].Attributes
	data, ok := attrs["data"].(map[string]any)
	if !ok {
		t.Fatalf("data = %+v, want a real map, not redacted wholesale (ConfigMap, not Secret)", attrs["data"])
	}
	if got, want := data["log_level"], "info"; got != want {
		t.Errorf("data.log_level = %v, want %q", got, want)
	}
}

// TestParseRedactsSecretShapedKeyRegardlessOfKind confirms the generic
// key-name pass still runs on every object, Secret or not - a
// non-Secret object with a field named e.g. "api_key" anywhere in it
// (a Deployment's env value, say) must still be caught.
func TestParseRedactsSecretShapedKeyRegardlessOfKind(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  api_key: abc123
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data := g.Resources[0].Attributes["data"].(map[string]any)
	if got := data["api_key"]; got != redact.Placeholder {
		t.Errorf("data.api_key = %v, want %q", got, redact.Placeholder)
	}
}
