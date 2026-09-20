package okta

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/provenance"
)

func TestCollectMFAEnrollmentPolicies(t *testing.T) {
	client := loadFakePolicyEndpoint(t, mfaPolicyType, "mfa_policies.json")
	graph, err := CollectMFAEnrollmentPolicies(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectMFAEnrollmentPolicies: %v", err)
	}
	if len(graph.Policies) != 3 {
		t.Fatalf("got %d policies, want 3", len(graph.Policies))
	}

	byID := make(map[string]MFAEnrollmentPolicy, len(graph.Policies))
	for _, p := range graph.Policies {
		byID[p.ID] = p
	}

	alpha := byID["policy-alpha"]
	if alpha.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("policy-alpha.Provenance.Confidence = %v, want Deterministic", alpha.Provenance.Confidence)
	}
	if alpha.Status != "ACTIVE" || alpha.Priority != 1 {
		t.Errorf("policy-alpha status/priority = %q/%d, want ACTIVE/1", alpha.Status, alpha.Priority)
	}
	wantFactors := map[string]string{
		"okta_verify": "REQUIRED",
		"okta_otp":    "OPTIONAL",
		"google_otp":  "NOT_ALLOWED",
	}
	for factor, want := range wantFactors {
		if got := alpha.Factors[factor]; got != want {
			t.Errorf("policy-alpha factor %s = %q, want %q", factor, got, want)
		}
	}

	beta := byID["policy-beta"]
	if beta.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("policy-beta.Provenance.Confidence = %v, want Deterministic", beta.Provenance.Confidence)
	}
	if beta.Status != "INACTIVE" {
		t.Errorf("policy-beta.Status = %q, want INACTIVE (a resolved inactive policy is still collected)", beta.Status)
	}
	if got, want := beta.Factors["okta_verify"], "OPTIONAL"; got != want {
		t.Errorf("policy-beta factor okta_verify = %q, want %q", got, want)
	}

	gamma := byID["policy-gamma"]
	if gamma.Provenance.Confidence != provenance.Unresolved {
		t.Fatalf("policy-gamma.Provenance.Confidence = %v, want Unresolved (malformed settings)", gamma.Provenance.Confidence)
	}
	if gamma.Provenance.UnresolvedReason == "" {
		t.Error("policy-gamma.Provenance.UnresolvedReason is empty")
	}
}

func TestCollectMFAEnrollmentPoliciesSortedByID(t *testing.T) {
	client := loadFakePolicyEndpoint(t, mfaPolicyType, "mfa_policies.json")
	graph, err := CollectMFAEnrollmentPolicies(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectMFAEnrollmentPolicies: %v", err)
	}
	for i := 1; i < len(graph.Policies); i++ {
		if graph.Policies[i-1].ID >= graph.Policies[i].ID {
			t.Fatalf("policies not sorted: %q >= %q", graph.Policies[i-1].ID, graph.Policies[i].ID)
		}
	}
}

func TestCollectMFAEnrollmentPoliciesPropagatesListError(t *testing.T) {
	client := newFakePolicyEndpoint()
	if _, err := CollectMFAEnrollmentPolicies(context.Background(), client, testObservedAt); err == nil {
		t.Fatal("CollectMFAEnrollmentPolicies succeeded, want an error when ListPolicies fails")
	}
}
