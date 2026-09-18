package fedramp20x

import (
	"encoding/json"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/rules"
)

// TestBuildInputZeroControlIndicatorSerializesAsEmptyArray guards against
// a real bug this package shipped and then found while adding a third
// KSI family module: an indicator with zero controls in the vendored
// dataset (e.g. KSI-CNA-OFA) built via append([]string(nil)) stayed a
// nil Go slice, which encoding/json renders as JSON null rather than [].
// count(null) is undefined in Rego, not 0 (confirmed directly against
// OPA) - every family module's "results contains result if
// count(indicator.controls) == 0" branch silently never matched, so the
// indicator vanished from Evaluate's output entirely instead of coming
// back not_applicable. This test round-trips buildInput's output through
// encoding/json and asserts the literal bytes, since a Go-level
// "!= nil" check wouldn't catch a regression back to append's nil-slice
// behavior the way inspecting the actual serialized JSON does.
func TestBuildInputZeroControlIndicatorSerializesAsEmptyArray(t *testing.T) {
	theme := rules.KSITheme{
		Indicators: map[string]rules.KSIIndicator{
			"KSI-TEST-EMPTY": {Controls: nil},
		},
	}
	got := buildInput(ir.Graph{}, theme)

	raw, err := json.Marshal(got.Indicators["KSI-TEST-EMPTY"])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	want := `{"controls":[]}`
	if string(raw) != want {
		t.Fatalf("serialized indicator = %s, want %s", raw, want)
	}
}

// TestBuildInputNodeWithNoControlsSerializesAsEmptyArray is the node-side
// analogue - already correct before this bug (buildInput's node loop
// uses make([]string, 0, ...), never append([]string(nil))) - kept here
// so both sides of the same shape are asserted the same way, rather than
// only the side that had the bug.
func TestBuildInputNodeWithNoControlsSerializesAsEmptyArray(t *testing.T) {
	g := ir.Graph{Nodes: []ir.Node{{ID: "test:no-controls", Kind: "test_fact"}}}
	got := buildInput(g, rules.KSITheme{})

	raw, err := json.Marshal(got.Nodes[0])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	want := `{"id":"test:no-controls","kind":"test_fact","controls":[],"attributes":{}}`
	if string(raw) != want {
		t.Fatalf("serialized node = %s, want %s", raw, want)
	}
}

// TestBuildInputNodeAttributesPassThrough proves a node's real
// measurements (ir.Node.Attributes) reach the Rego input at all - until
// this ticket, regoNode had no Attributes field, so no predicate module
// could ever inspect a collected value, only whether a control was
// evidenced.
func TestBuildInputNodeAttributesPassThrough(t *testing.T) {
	g := ir.Graph{Nodes: []ir.Node{{
		ID:         "test:with-attrs",
		Kind:       "s3_bucket_public_access_block",
		Attributes: map[string]string{"block_public_acls": "true", "block_public_policy": "false"},
	}}}
	got := buildInput(g, rules.KSITheme{})

	if got.Nodes[0].Attributes["block_public_acls"] != "true" {
		t.Errorf("Attributes[block_public_acls] = %q, want %q", got.Nodes[0].Attributes["block_public_acls"], "true")
	}
	if got.Nodes[0].Attributes["block_public_policy"] != "false" {
		t.Errorf("Attributes[block_public_policy] = %q, want %q", got.Nodes[0].Attributes["block_public_policy"], "false")
	}
}
