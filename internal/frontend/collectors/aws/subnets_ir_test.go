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

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	// 4 subnets x 1 topology node each = 4. Routing nodes: subnet-public,
	// subnet-private, subnet-fallback resolve (3); subnet-orphan's
	// routing is unresolved, no node. 4 + 3 = 7.
	if len(irGraph.Nodes) != 7 {
		t.Fatalf("got %d nodes, want 7 (4 topology + 3 routing; subnet-orphan's routing unresolved)", len(irGraph.Nodes))
	}

	topologyID := awsNodeID("subnet", "subnet-public", "topology")
	pub, ok := byID[topologyID]
	if !ok {
		t.Fatal("no topology node for subnet-public")
	}
	if pub.ControlFamily != "SC" || len(pub.Controls) != 1 || pub.Controls[0] != (ir.Control{Family: "SC", Base: 7}) {
		t.Errorf("subnet-public topology control = %+v/%+v, want SC/SC-7", pub.ControlFamily, pub.Controls)
	}
	if pub.Kind != "aws_subnet" {
		t.Errorf("subnet-public topology Kind = %q, want aws_subnet", pub.Kind)
	}
	wantAttrs := map[string]string{
		"vpc_id":                  "vpc-1",
		"cidr":                    "10.0.1.0/24",
		"availability_zone":       "us-east-1a",
		"map_public_ip_on_launch": "true",
	}
	for k, want := range wantAttrs {
		if got := pub.Attributes[k]; got != want {
			t.Errorf("subnet-public topology attribute %s = %q, want %q", k, got, want)
		}
	}
	if pub.Provenance.Basis != "observed" {
		t.Errorf("subnet-public topology Provenance.Basis = %q, want observed", pub.Provenance.Basis)
	}

	routingID := awsNodeID("subnet", "subnet-public", "routing")
	pubRouting, ok := byID[routingID]
	if !ok {
		t.Fatal("no routing node for subnet-public")
	}
	if pubRouting.Kind != "aws_subnet_routing" {
		t.Errorf("subnet-public routing Kind = %q, want aws_subnet_routing", pubRouting.Kind)
	}
	if pubRouting.ControlFamily != "SC" || len(pubRouting.Controls) != 1 || pubRouting.Controls[0] != (ir.Control{Family: "SC", Base: 7}) {
		t.Errorf("subnet-public routing control = %+v/%+v, want SC/SC-7 (same control as the topology node)", pubRouting.ControlFamily, pubRouting.Controls)
	}
	if got, want := pubRouting.Attributes["has_internet_gateway_route"], "true"; got != want {
		t.Errorf("subnet-public routing has_internet_gateway_route = %q, want %q", got, want)
	}
	if got, want := pubRouting.Attributes["internet_gateway_route_destination"], "0.0.0.0/0"; got != want {
		t.Errorf("subnet-public routing internet_gateway_route_destination = %q, want %q", got, want)
	}
	if got, want := pubRouting.Attributes["route_table_id"], "rt-public"; got != want {
		t.Errorf("subnet-public routing route_table_id = %q, want %q", got, want)
	}

	privRoutingID := awsNodeID("subnet", "subnet-private", "routing")
	privRouting, ok := byID[privRoutingID]
	if !ok {
		t.Fatal("no routing node for subnet-private")
	}
	if got, want := privRouting.Attributes["has_internet_gateway_route"], "false"; got != want {
		t.Errorf("subnet-private routing has_internet_gateway_route = %q, want %q", got, want)
	}
	if _, present := privRouting.Attributes["internet_gateway_route_destination"]; present {
		t.Error("subnet-private routing has internet_gateway_route_destination set, want it omitted when there's no igw route")
	}

	fallbackRoutingID := awsNodeID("subnet", "subnet-fallback", "routing")
	if _, ok := byID[fallbackRoutingID]; !ok {
		t.Error("no routing node for subnet-fallback, want one resolved via the VPC main route table fallback")
	}

	orphanRoutingID := awsNodeID("subnet", "subnet-orphan", "routing")
	if _, ok := byID[orphanRoutingID]; ok {
		t.Error("subnet-orphan has a routing node, want none (its route table could not be resolved)")
	}
	// subnet-orphan's topology node must still exist independently.
	orphanTopologyID := awsNodeID("subnet", "subnet-orphan", "topology")
	if _, ok := byID[orphanTopologyID]; !ok {
		t.Error("subnet-orphan has no topology node, want one - an unresolved routing join must not suppress the subnet's own already-resolved facts")
	}
}
