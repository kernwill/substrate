package okta

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

var testObservedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// fakePolicyEndpoint implements OktaAPI by serving canned RawPolicy
// data loaded from this package's testdata fixtures (FR-3.10), keyed by
// policy type - the same fixture-substitution pattern aws's fakeS3
// uses, adapted for this package's one shared ListPolicies operation.
type fakePolicyEndpoint struct {
	byType map[string][]RawPolicy
}

func loadFakePolicyEndpoint(t *testing.T, policyType, fixture string) *fakePolicyEndpoint {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + fixture)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", fixture, err)
	}
	var policies []RawPolicy
	if err := json.Unmarshal(raw, &policies); err != nil {
		t.Fatalf("parse testdata/%s: %v", fixture, err)
	}
	return &fakePolicyEndpoint{byType: map[string][]RawPolicy{policyType: policies}}
}

func (f *fakePolicyEndpoint) ListPolicies(ctx context.Context, policyType string) ([]RawPolicy, error) {
	policies, ok := f.byType[policyType]
	if !ok {
		return nil, errors.New("fakePolicyEndpoint: no fixture registered for policy type " + policyType)
	}
	return policies, nil
}

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
	client := &fakePolicyEndpoint{byType: map[string][]RawPolicy{}}
	if _, err := CollectMFAEnrollmentPolicies(context.Background(), client, testObservedAt); err == nil {
		t.Fatal("CollectMFAEnrollmentPolicies succeeded, want an error when ListPolicies fails")
	}
}
