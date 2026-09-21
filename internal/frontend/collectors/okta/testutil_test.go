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
	byType       map[string][]RawPolicy
	byRules      map[string][]RawPolicyRule
	events       []RawLogEvent
	eventsErr    error
	users        []RawUser
	usersErr     error
	byUserRoles  map[string][]RawUserRole
	userRolesErr map[string]error
}

func newFakePolicyEndpoint() *fakePolicyEndpoint {
	return &fakePolicyEndpoint{
		byType:       make(map[string][]RawPolicy),
		byRules:      make(map[string][]RawPolicyRule),
		byUserRoles:  make(map[string][]RawUserRole),
		userRolesErr: make(map[string]error),
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

// withUsers registers fixture as ListUsers' response.
func (f *fakePolicyEndpoint) withUsers(t *testing.T, fixture string) *fakePolicyEndpoint {
	t.Helper()
	var users []RawUser
	readTestdataJSON(t, fixture, &users)
	f.users = users
	return f
}

// withUsersError makes ListUsers fail.
func (f *fakePolicyEndpoint) withUsersError(err error) *fakePolicyEndpoint {
	f.usersErr = err
	return f
}

// withUserRoles registers fixture as ListUserRoles(userID)'s response.
func (f *fakePolicyEndpoint) withUserRoles(t *testing.T, userID, fixture string) *fakePolicyEndpoint {
	t.Helper()
	var roles []RawUserRole
	readTestdataJSON(t, fixture, &roles)
	f.byUserRoles[userID] = roles
	return f
}

// withUserRolesError makes ListUserRoles(userID) fail for that one user
// only, for testing that a single user's failure doesn't take down the
// whole collection run.
func (f *fakePolicyEndpoint) withUserRolesError(userID string, err error) *fakePolicyEndpoint {
	f.userRolesErr[userID] = err
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

func (f *fakePolicyEndpoint) ListUsers(ctx context.Context) ([]RawUser, error) {
	if f.usersErr != nil {
		return nil, f.usersErr
	}
	return f.users, nil
}

func (f *fakePolicyEndpoint) ListUserRoles(ctx context.Context, userID string) ([]RawUserRole, error) {
	if err, ok := f.userRolesErr[userID]; ok {
		return nil, err
	}
	roles, ok := f.byUserRoles[userID]
	if !ok {
		return nil, errors.New("fakePolicyEndpoint: no roles fixture registered for user " + userID)
	}
	return roles, nil
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
