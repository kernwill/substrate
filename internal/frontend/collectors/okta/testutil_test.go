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

// fakePolicyEndpoint implements OktaAPI by serving canned RawPolicy,
// RawPolicyRule, and RawLogEvent data loaded from this package's
// testdata fixtures (FR-3.10) - the same fixture-substitution pattern
// aws's fakeS3 uses, adapted for this package's three OktaAPI
// operations. Named for the policy endpoints it originally covered;
// kept rather than renamed when ListSystemLogEvents was added, to avoid
// unrelated churn across every file that already references it.
type fakePolicyEndpoint struct {
	byType    map[string][]RawPolicy
	byRules   map[string][]RawPolicyRule
	events    []RawLogEvent
	eventsErr error
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

// withLogEvents registers fixture as ListSystemLogEvents' response,
// regardless of the since/until/eventTypes it's called with - this
// package's tests only ever need one canned event set per test, not a
// filter-aware fake.
func (f *fakePolicyEndpoint) withLogEvents(t *testing.T, fixture string) *fakePolicyEndpoint {
	t.Helper()
	var events []RawLogEvent
	readTestdataJSON(t, fixture, &events)
	f.events = events
	return f
}

// withLogEventsError makes ListSystemLogEvents fail, for testing that a
// System Log failure propagates rather than being swallowed.
func (f *fakePolicyEndpoint) withLogEventsError(err error) *fakePolicyEndpoint {
	f.eventsErr = err
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

func (f *fakePolicyEndpoint) ListSystemLogEvents(ctx context.Context, since, until time.Time, eventTypes []string) ([]RawLogEvent, error) {
	if f.eventsErr != nil {
		return nil, f.eventsErr
	}
	return f.events, nil
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
