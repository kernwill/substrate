package okta

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestSessionPolicyToIR(t *testing.T) {
	client := newFakePolicyEndpoint().
		withPolicies(t, sessionPolicyType, "session_policies.json").
		withRules(t, "sp-alpha", "session_policy_rules_alpha.json")

	graph, err := CollectSessionPolicies(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSessionPolicies: %v", err)
	}
	irGraph, err := SessionPolicyToIR(graph)
	if err != nil {
		t.Fatalf("SessionPolicyToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// rule-1 resolved -> 1 node. rule-2's actions never parsed, and
	// sp-beta's rules were never listed -> 0 nodes for either.
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (only sp-alpha/rule-1 resolved)", len(irGraph.Nodes))
	}

	nodeID := oktaNodeID("session-policy", "sp-alpha/rule-1", "session-termination")
	node := irGraph.Nodes[0]
	if node.ID != nodeID {
		t.Fatalf("node.ID = %q, want %q", node.ID, nodeID)
	}
	if node.ControlFamily != "AC" || len(node.Controls) != 1 || node.Controls[0] != (ir.Control{Family: "AC", Base: 12}) {
		t.Errorf("node control = %+v/%+v, want AC/AC-12", node.ControlFamily, node.Controls)
	}
	if node.Kind != "okta_session_policy_rule" {
		t.Errorf("node.Kind = %q, want okta_session_policy_rule", node.Kind)
	}
	wantAttrs := map[string]string{
		"max_session_idle_minutes":     "120",
		"max_session_lifetime_minutes": "720",
		"use_persistent_cookie":        "false",
		"policy_name":                  "Default Sign-On Policy",
		"rule_name":                    "Default Rule",
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
