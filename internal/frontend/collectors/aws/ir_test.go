package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestToIR(t *testing.T) {
	client := loadFakeS3(t)
	graph, err := CollectS3(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectS3: %v", err)
	}
	irGraph, err := ToIR(graph)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	// alpha: both encryption and public-access-block resolved -> 2 nodes.
	// beta: encryption resolved, PAB unresolved -> 1 node.
	// gamma: both resolved (logging is the only unresolved field, and
	// logging isn't mapped at all yet) -> 2 nodes.
	// delta: nothing resolved -> 0 nodes.
	if len(irGraph.Nodes) != 5 {
		t.Fatalf("got %d nodes, want 5 (alpha x2, beta x1, gamma x2, delta x0)", len(irGraph.Nodes))
	}

	enc, ok := byID[nodeID("alpha", "encryption")]
	if !ok {
		t.Fatal("no alpha encryption node")
	}
	if enc.ControlFamily != "SC" || len(enc.Controls) != 1 || enc.Controls[0] != (ir.Control{Family: "SC", Base: 28, Enhancement: 1}) {
		t.Errorf("alpha encryption control = %+v/%+v, want SC/SC-28(1)", enc.ControlFamily, enc.Controls)
	}
	if got, want := enc.Attributes["sse_algorithm"], "aws:kms"; got != want {
		t.Errorf("alpha sse_algorithm = %q, want %q", got, want)
	}
	if enc.Provenance.Basis != "observed" {
		t.Errorf("alpha encryption Provenance.Basis = %q, want observed", enc.Provenance.Basis)
	}

	pab, ok := byID[nodeID("alpha", "public-access-block")]
	if !ok {
		t.Fatal("no alpha public-access-block node")
	}
	if pab.ControlFamily != "AC" || len(pab.Controls) != 1 || pab.Controls[0] != (ir.Control{Family: "AC", Base: 3}) {
		t.Errorf("alpha public-access-block control = %+v/%+v, want AC/AC-3", pab.ControlFamily, pab.Controls)
	}
	for _, flag := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		if got, want := pab.Attributes[flag], "true"; got != want {
			t.Errorf("alpha %s = %q, want %q", flag, got, want)
		}
	}

	if _, ok := byID[nodeID("beta", "public-access-block")]; ok {
		t.Error("beta has a public-access-block node, want none (no bucket-level config, never guessed)")
	}
	if _, ok := byID[nodeID("beta", "encryption")]; !ok {
		t.Error("beta has no encryption node, want one (encryption resolved)")
	}

	if _, ok := byID[nodeID("delta", "encryption")]; ok {
		t.Error("delta has an encryption node, want none (nothing resolved for delta)")
	}
	if _, ok := byID[nodeID("delta", "public-access-block")]; ok {
		t.Error("delta has a public-access-block node, want none (nothing resolved for delta)")
	}
}
