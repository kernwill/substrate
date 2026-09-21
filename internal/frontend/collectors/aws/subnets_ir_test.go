package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestSubnetsToIR(t *testing.T) {
	client := loadFakeSubnets(t)
	graph, err := CollectSubnets(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSubnets: %v", err)
	}
	irGraph, err := SubnetsToIR(graph)
	if err != nil {
		t.Fatalf("SubnetsToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (one per subnet)", len(irGraph.Nodes))
	}

	nodeID := awsNodeID("subnet", "subnet-public", "topology")
	var pub *ir.Node
	for i := range irGraph.Nodes {
		if irGraph.Nodes[i].ID == nodeID {
			pub = &irGraph.Nodes[i]
		}
	}
	if pub == nil {
		t.Fatal("no node for subnet-public")
	}
	if pub.ControlFamily != "SC" || len(pub.Controls) != 1 || pub.Controls[0] != (ir.Control{Family: "SC", Base: 7}) {
		t.Errorf("subnet-public control = %+v/%+v, want SC/SC-7", pub.ControlFamily, pub.Controls)
	}
	if pub.Kind != "aws_subnet" {
		t.Errorf("subnet-public.Kind = %q, want aws_subnet", pub.Kind)
	}
	wantAttrs := map[string]string{
		"vpc_id":                  "vpc-1",
		"cidr":                    "10.0.1.0/24",
		"availability_zone":       "us-east-1a",
		"map_public_ip_on_launch": "true",
	}
	for k, want := range wantAttrs {
		if got := pub.Attributes[k]; got != want {
			t.Errorf("subnet-public attribute %s = %q, want %q", k, got, want)
		}
	}
	if pub.Provenance.Basis != "observed" {
		t.Errorf("subnet-public Provenance.Basis = %q, want observed", pub.Provenance.Basis)
	}

	privNodeID := awsNodeID("subnet", "subnet-private", "topology")
	var priv *ir.Node
	for i := range irGraph.Nodes {
		if irGraph.Nodes[i].ID == privNodeID {
			priv = &irGraph.Nodes[i]
		}
	}
	if priv == nil {
		t.Fatal("no node for subnet-private")
	}
	if got, want := priv.Attributes["map_public_ip_on_launch"], "false"; got != want {
		t.Errorf("subnet-private map_public_ip_on_launch = %q, want %q", got, want)
	}
}
