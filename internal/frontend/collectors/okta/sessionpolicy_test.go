package okta

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/provenance"
)

func TestCollectSessionPolicies(t *testing.T) {
	client := newFakePolicyEndpoint().
		withPolicies(t, sessionPolicyType, "session_policies.json").
		withRules(t, "sp-alpha", "session_policy_rules_alpha.json")
		// sp-beta deliberately has no rules fixture registered, to
		// exercise the whole-policy ListPolicyRules failure path.

	graph, err := CollectSessionPolicies(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSessionPolicies: %v", err)
	}
	if len(graph.Rules) != 3 {
		t.Fatalf("got %d rules, want 3 (sp-alpha's 2 rules, sp-beta's 1 unresolved placeholder)", len(graph.Rules))
	}

	byRuleID := make(map[string]SessionPolicyRule, len(graph.Rules))
	for _, r := range graph.Rules {
		byRuleID[r.PolicyID+"/"+r.RuleID] = r
	}

	rule1 := byRuleID["sp-alpha/rule-1"]
	if rule1.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("sp-alpha/rule-1.Provenance.Confidence = %v, want Deterministic", rule1.Provenance.Confidence)
	}
	if rule1.MaxSessionIdleMinutes != 120 {
		t.Errorf("sp-alpha/rule-1.MaxSessionIdleMinutes = %d, want 120", rule1.MaxSessionIdleMinutes)
	}
	if rule1.MaxSessionLifetimeMinutes != 720 {
		t.Errorf("sp-alpha/rule-1.MaxSessionLifetimeMinutes = %d, want 720", rule1.MaxSessionLifetimeMinutes)
	}
	if rule1.UsePersistentCookie {
		t.Error("sp-alpha/rule-1.UsePersistentCookie = true, want false")
	}

	rule2 := byRuleID["sp-alpha/rule-2"]
	if rule2.Provenance.Confidence != provenance.Unresolved {
		t.Fatalf("sp-alpha/rule-2.Provenance.Confidence = %v, want Unresolved (malformed actions)", rule2.Provenance.Confidence)
	}
	if rule2.Provenance.UnresolvedReason == "" {
		t.Error("sp-alpha/rule-2.Provenance.UnresolvedReason is empty")
	}

	betaPlaceholder := byRuleID["sp-beta/"]
	if betaPlaceholder.Provenance.Confidence != provenance.Unresolved {
		t.Fatalf("sp-beta placeholder.Provenance.Confidence = %v, want Unresolved (rules could not be listed)", betaPlaceholder.Provenance.Confidence)
	}
	if betaPlaceholder.PolicyName != "No Rules Policy" {
		t.Errorf("sp-beta placeholder.PolicyName = %q, want %q", betaPlaceholder.PolicyName, "No Rules Policy")
	}
}

func TestCollectSessionPoliciesSorted(t *testing.T) {
	client := newFakePolicyEndpoint().
		withPolicies(t, sessionPolicyType, "session_policies.json").
		withRules(t, "sp-alpha", "session_policy_rules_alpha.json")

	graph, err := CollectSessionPolicies(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSessionPolicies: %v", err)
	}
	for i := 1; i < len(graph.Rules); i++ {
		a, b := graph.Rules[i-1], graph.Rules[i]
		if a.PolicyID > b.PolicyID || (a.PolicyID == b.PolicyID && a.RuleID > b.RuleID) {
			t.Fatalf("rules not sorted: %s/%s before %s/%s", a.PolicyID, a.RuleID, b.PolicyID, b.RuleID)
		}
	}
}

func TestCollectSessionPoliciesPropagatesListError(t *testing.T) {
	client := newFakePolicyEndpoint()
	if _, err := CollectSessionPolicies(context.Background(), client, testObservedAt); err == nil {
		t.Fatal("CollectSessionPolicies succeeded, want an error when ListPolicies fails")
	}
}
