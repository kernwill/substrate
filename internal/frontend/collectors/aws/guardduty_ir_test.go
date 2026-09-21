package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestGuardDutyToIR(t *testing.T) {
	client := loadFakeGuardDuty(t)
	graph, err := CollectGuardDuty(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectGuardDuty: %v", err)
	}
	irGraph, err := GuardDutyToIR(graph)
	if err != nil {
		t.Fatalf("GuardDutyToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// detector-good and detector-off resolved -> 2 nodes; detector-error
	// unresolved -> 0 nodes for it.
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (detector-good, detector-off; detector-error unresolved)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	goodID := awsNodeID("guardduty", "detector-good", "enablement")
	good, ok := byID[goodID]
	if !ok {
		t.Fatal("no node for detector-good")
	}
	if good.ControlFamily != "SI" || len(good.Controls) != 1 || good.Controls[0] != (ir.Control{Family: "SI", Base: 4}) {
		t.Errorf("detector-good control = %+v/%+v, want SI/SI-4", good.ControlFamily, good.Controls)
	}
	if good.Kind != "aws_guardduty_detector" {
		t.Errorf("detector-good.Kind = %q, want aws_guardduty_detector", good.Kind)
	}
	wantAttrs := map[string]string{
		"present":                      "true",
		"enabled":                      "true",
		"finding_publishing_frequency": "FIFTEEN_MINUTES",
	}
	for k, want := range wantAttrs {
		if got := good.Attributes[k]; got != want {
			t.Errorf("detector-good attribute %s = %q, want %q", k, got, want)
		}
	}
	if good.Provenance.Basis != "observed" {
		t.Errorf("detector-good Provenance.Basis = %q, want observed", good.Provenance.Basis)
	}

	offID := awsNodeID("guardduty", "detector-off", "enablement")
	off, ok := byID[offID]
	if !ok {
		t.Fatal("no node for detector-off")
	}
	if got, want := off.Attributes["enabled"], "false"; got != want {
		t.Errorf("detector-off enabled = %q, want %q (a resolved false must still produce a node)", got, want)
	}
}

// TestGuardDutyToIRNoDetectors confirms the synthetic Present:false fact
// (no GuardDuty detector exists at all) still produces a real IR node -
// this is a resolved, deterministic negative, not silence.
func TestGuardDutyToIRNoDetectors(t *testing.T) {
	client := &fakeGuardDuty{detectors: map[string]struct {
		Status                     string
		FindingPublishingFrequency string
		Err                        string
	}{}}
	graph, err := CollectGuardDuty(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectGuardDuty: %v", err)
	}
	irGraph, err := GuardDutyToIR(graph)
	if err != nil {
		t.Fatalf("GuardDutyToIR: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (the confirmed-absent detector fact)", len(irGraph.Nodes))
	}
	node := irGraph.Nodes[0]
	if got, want := node.Attributes["present"], "false"; got != want {
		t.Errorf("present = %q, want %q", got, want)
	}
	wantID := awsNodeID("guardduty", "none", "enablement")
	if node.ID != wantID {
		t.Errorf("node.ID = %q, want %q", node.ID, wantID)
	}
}
