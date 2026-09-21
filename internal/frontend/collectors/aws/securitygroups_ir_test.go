package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestSecurityGroupsToIR(t *testing.T) {
	client := loadFakeSecurityGroups(t)
	graph, err := CollectSecurityGroups(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityGroups: %v", err)
	}
	irGraph, err := SecurityGroupsToIR(graph)
	if err != nil {
		t.Fatalf("SecurityGroupsToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if len(irGraph.Nodes) != len(graph.Rules) {
		t.Fatalf("got %d nodes, want %d (one per collected rule)", len(irGraph.Nodes), len(graph.Rules))
	}

	var openSSH *ir.Node
	for i := range irGraph.Nodes {
		if irGraph.Nodes[i].Attributes["cidr"] == "0.0.0.0/0" && irGraph.Nodes[i].Attributes["direction"] == "ingress" {
			openSSH = &irGraph.Nodes[i]
			break
		}
	}
	if openSSH == nil {
		t.Fatal("no node for sg-open-ssh's 0.0.0.0/0 ingress rule")
	}
	if openSSH.ControlFamily != "SC" || len(openSSH.Controls) != 1 || openSSH.Controls[0] != (ir.Control{Family: "SC", Base: 7, Enhancement: 5}) {
		t.Errorf("open-ssh rule control = %+v/%+v, want SC/SC-7(5)", openSSH.ControlFamily, openSSH.Controls)
	}
	if openSSH.Kind != "aws_security_group_rule" {
		t.Errorf("open-ssh rule Kind = %q, want aws_security_group_rule", openSSH.Kind)
	}
	wantAttrs := map[string]string{
		"protocol":  "tcp",
		"from_port": "22",
		"to_port":   "22",
		"vpc_id":    "vpc-1",
	}
	for k, want := range wantAttrs {
		if got := openSSH.Attributes[k]; got != want {
			t.Errorf("open-ssh rule attribute %s = %q, want %q", k, got, want)
		}
	}
	if openSSH.Provenance.Basis != "observed" {
		t.Errorf("open-ssh rule Provenance.Basis = %q, want observed", openSSH.Provenance.Basis)
	}

	var allProtocolsEgress *ir.Node
	for i := range irGraph.Nodes {
		if irGraph.Nodes[i].Attributes["protocol"] == "-1" {
			allProtocolsEgress = &irGraph.Nodes[i]
			break
		}
	}
	if allProtocolsEgress == nil {
		t.Fatal("no node for sg-restricted's all-protocols egress rule")
	}
	if got, want := allProtocolsEgress.Attributes["from_port"], "any"; got != want {
		t.Errorf("all-protocols egress from_port = %q, want %q (no port range, not a guessed number)", got, want)
	}
	if got, want := allProtocolsEgress.Attributes["to_port"], "any"; got != want {
		t.Errorf("all-protocols egress to_port = %q, want %q", got, want)
	}
}
