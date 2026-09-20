package okta

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

var testObservedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// fakePolicyEndpoint implements OktaAPI by serving canned RawPolicy and
// RawPolicyRule data loaded from this package's testdata fixtures
// (FR-3.10) - the same fixture-substitution pattern aws's fakeS3 uses,
// adapted for this package's shared policy/rules operations.
type fakePolicyEndpoint struct {
	byType  map[string][]RawPolicy
	byRules map[string][]RawPolicyRule
}

func newFakePolicyEndpoint() *fakePolicyEndpoint {
	return &fakePolicyEndpoint{
		byType:  make(map[string][]RawPolicy),
		byRules: make(map[string][]RawPolicyRule),
	}
}

// withPolicies registers fixture as the response for ListPolicies(policyType).
func (f *fakePolicyEndpoint) withPolicies(t *testing.T, policyType, fixture string) *fakePolicyEndpoint {
	t.Helper()
	var policies []RawPolicy
	readTestdataJSON(t, fixture, &policies)
	f.byType[policyType] = policies
	return f
}

// withRules registers fixture as the response for ListPolicyRules(policyID).
func (f *fakePolicyEndpoint) withRules(t *testing.T, policyID, fixture string) *fakePolicyEndpoint {
	t.Helper()
	var rules []RawPolicyRule
	readTestdataJSON(t, fixture, &rules)
	f.byRules[policyID] = rules
	return f
}

func loadFakePolicyEndpoint(t *testing.T, policyType, fixture string) *fakePolicyEndpoint {
	t.Helper()
	return newFakePolicyEndpoint().withPolicies(t, policyType, fixture)
}

func (f *fakePolicyEndpoint) ListPolicies(ctx context.Context, policyType string) ([]RawPolicy, error) {
	policies, ok := f.byType[policyType]
	if !ok {
		return nil, errors.New("fakePolicyEndpoint: no fixture registered for policy type " + policyType)
	}
	return policies, nil
}

func (f *fakePolicyEndpoint) ListPolicyRules(ctx context.Context, policyID string) ([]RawPolicyRule, error) {
	rules, ok := f.byRules[policyID]
	if !ok {
		return nil, errors.New("fakePolicyEndpoint: no rules fixture registered for policy " + policyID)
	}
	return rules, nil
}

// readTestdataJSON reads testdata/<name> and unmarshals it into v,
// failing the test loudly on either error - mirrors
// aws.readTestdataJSON exactly.
func readTestdataJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse testdata/%s: %v", name, err)
	}
}
