package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/kernwill/substrate/internal/ir"
)

func TestSecurityHubToIR(t *testing.T) {
	client := &fakeSecurityHub{out: &securityhub.DescribeHubOutput{
		HubArn:             strPtr("arn:aws:securityhub:us-east-1:123456789012:hub/default"),
		SubscribedAt:       strPtr("2026-01-01T00:00:00.000Z"),
		AutoEnableControls: boolPtr(true),
	}}
	graph, err := CollectSecurityHub(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityHub: %v", err)
	}
	irGraph, err := SecurityHubToIR(graph)
	if err != nil {
		t.Fatalf("SecurityHubToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(irGraph.Nodes))
	}

	node := irGraph.Nodes[0]
	wantID := awsNodeID("securityhub", "arn:aws:securityhub:us-east-1:123456789012:hub/default", "enablement")
	if node.ID != wantID {
		t.Errorf("node.ID = %q, want %q", node.ID, wantID)
	}
	if node.ControlFamily != "CA" || len(node.Controls) != 1 || node.Controls[0] != (ir.Control{Family: "CA", Base: 7}) {
		t.Errorf("control = %+v/%+v, want CA/CA-7", node.ControlFamily, node.Controls)
	}
	if node.Kind != "aws_securityhub_hub" {
		t.Errorf("Kind = %q, want aws_securityhub_hub", node.Kind)
	}
	wantAttrs := map[string]string{
		"present":              "true",
		"subscribed_at":        "2026-01-01T00:00:00.000Z",
		"auto_enable_controls": "true",
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

// TestSecurityHubToIRNotSubscribed confirms the synthetic Present:false
// fact still produces a real IR node - a resolved, deterministic
// negative, not silence.
func TestSecurityHubToIRNotSubscribed(t *testing.T) {
	client := &fakeSecurityHub{err: &types.InvalidAccessException{
		Message: strPtr("Account 123456789012 is not subscribed to AWS Security Hub"),
	}}
	graph, err := CollectSecurityHub(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityHub: %v", err)
	}
	irGraph, err := SecurityHubToIR(graph)
	if err != nil {
		t.Fatalf("SecurityHubToIR: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (the confirmed-not-subscribed fact)", len(irGraph.Nodes))
	}
	node := irGraph.Nodes[0]
	if got, want := node.Attributes["present"], "false"; got != want {
		t.Errorf("present = %q, want %q", got, want)
	}
	wantID := awsNodeID("securityhub", "none", "enablement")
	if node.ID != wantID {
		t.Errorf("node.ID = %q, want %q", node.ID, wantID)
	}
}
