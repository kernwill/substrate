package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestConfigToIR(t *testing.T) {
	client := loadFakeConfig(t)
	graph, err := CollectConfig(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectConfig: %v", err)
	}
	irGraph, err := ConfigToIR(graph)
	if err != nil {
		t.Fatalf("ConfigToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(irGraph.Nodes))
	}

	node := irGraph.Nodes[0]
	wantID := awsNodeID("config", "default", "enablement")
	if node.ID != wantID {
		t.Errorf("node.ID = %q, want %q", node.ID, wantID)
	}
	if node.ControlFamily != "CM" || len(node.Controls) != 1 || node.Controls[0] != (ir.Control{Family: "CM", Base: 6}) {
		t.Errorf("control = %+v/%+v, want CM/CM-6", node.ControlFamily, node.Controls)
	}
	if node.Kind != "aws_config_recorder" {
		t.Errorf("Kind = %q, want aws_config_recorder", node.Kind)
	}
	wantAttrs := map[string]string{
		"present":     "true",
		"recording":   "true",
		"last_status": "Success",
	}
	for k, want := range wantAttrs {
		if got := node.Attributes[k]; got != want {
			t.Errorf("attribute %s = %q, want %q", k, got, want)
		}
	}
	if node.Provenance.Basis != "observed" {
		t.Errorf("Provenance.Basis = %q, want observed", node.Provenance.Basis)
	}
}

// TestConfigToIRNoRecorders confirms the synthetic Present:false fact
// (no AWS Config recorder exists at all) still produces a real IR node -
// a resolved, deterministic negative, not silence.
func TestConfigToIRNoRecorders(t *testing.T) {
	client := &fakeConfig{}
	graph, err := CollectConfig(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectConfig: %v", err)
	}
	irGraph, err := ConfigToIR(graph)
	if err != nil {
		t.Fatalf("ConfigToIR: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (the confirmed-absent recorder fact)", len(irGraph.Nodes))
	}
	node := irGraph.Nodes[0]
	if got, want := node.Attributes["present"], "false"; got != want {
		t.Errorf("present = %q, want %q", got, want)
	}
	wantID := awsNodeID("config", "none", "enablement")
	if node.ID != wantID {
		t.Errorf("node.ID = %q, want %q", node.ID, wantID)
	}
}
