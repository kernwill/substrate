package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestKMSToIR(t *testing.T) {
	client := loadFakeKMS(t)
	graph, err := CollectKMS(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectKMS: %v", err)
	}
	irGraph, err := KMSToIR(graph)
	if err != nil {
		t.Fatalf("KMSToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// key-customer-rotated and key-customer-not-rotated resolved -> 2
	// nodes; key-customer-error unresolved -> 0 nodes for it.
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (key-customer-error unresolved)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	rotatedID := awsNodeID("kms-key", "key-customer-rotated", "rotation")
	rotated, ok := byID[rotatedID]
	if !ok {
		t.Fatal("no node for key-customer-rotated")
	}
	if rotated.ControlFamily != "SC" || len(rotated.Controls) != 1 || rotated.Controls[0] != (ir.Control{Family: "SC", Base: 12}) {
		t.Errorf("key-customer-rotated control = %+v/%+v, want SC/SC-12", rotated.ControlFamily, rotated.Controls)
	}
	if rotated.Kind != "aws_kms_key_rotation" {
		t.Errorf("Kind = %q, want aws_kms_key_rotation", rotated.Kind)
	}
	if got, want := rotated.Attributes["rotation_enabled"], "true"; got != want {
		t.Errorf("rotation_enabled = %q, want %q", got, want)
	}
	if got, want := rotated.Attributes["key_state"], "Enabled"; got != want {
		t.Errorf("key_state = %q, want %q", got, want)
	}
	if rotated.Provenance.Basis != "observed" {
		t.Errorf("Provenance.Basis = %q, want observed", rotated.Provenance.Basis)
	}

	notRotatedID := awsNodeID("kms-key", "key-customer-not-rotated", "rotation")
	notRotated, ok := byID[notRotatedID]
	if !ok {
		t.Fatal("no node for key-customer-not-rotated")
	}
	if got, want := notRotated.Attributes["rotation_enabled"], "false"; got != want {
		t.Errorf("key-customer-not-rotated rotation_enabled = %q, want %q (a resolved false must still produce a node)", got, want)
	}

	errID := awsNodeID("kms-key", "key-customer-error", "rotation")
	if _, ok := byID[errID]; ok {
		t.Error("key-customer-error has a node, want none (rotation status unresolved)")
	}
}
