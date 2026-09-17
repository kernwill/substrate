package aws

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/ir"
)

func TestIAMToIR(t *testing.T) {
	client := loadFakeIAM(t)
	graph, err := CollectIAM(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectIAM: %v", err)
	}
	irGraph, err := IAMToIR(graph)
	if err != nil {
		t.Fatalf("IAMToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	// alice, bob, dave, erin each resolve both facts (2 nodes apiece);
	// carol's MFA and access-key calls both error, so she contributes none.
	if len(irGraph.Nodes) != 8 {
		t.Fatalf("got %d nodes, want 8 (4 users x 2 facts; carol is fully unresolved)", len(irGraph.Nodes))
	}

	mfa, ok := byID[iamNodeID("alice", "mfa-devices")]
	if !ok {
		t.Fatal("no alice mfa-devices node")
	}
	if mfa.ControlFamily != "IA" || len(mfa.Controls) != 1 || mfa.Controls[0] != (ir.Control{Family: "IA", Base: 2}) {
		t.Errorf("alice mfa control = %+v/%+v, want IA/IA-2 (base, not an enhancement)", mfa.ControlFamily, mfa.Controls)
	}
	if got, want := mfa.Attributes["mfa_device_count"], "2"; got != want {
		t.Errorf("alice mfa_device_count = %q, want %q", got, want)
	}
	if mfa.Provenance.Basis != "observed" {
		t.Errorf("alice mfa Provenance.Basis = %q, want observed", mfa.Provenance.Basis)
	}

	// A zero MFA count is a real measurement, not an absence - it is
	// exactly the case a backend predicate over IA-2 exists to catch.
	bobMFA, ok := byID[iamNodeID("bob", "mfa-devices")]
	if !ok {
		t.Fatal("no bob mfa-devices node - a zero device count must still produce a node")
	}
	if got, want := bobMFA.Attributes["mfa_device_count"], "0"; got != want {
		t.Errorf("bob mfa_device_count = %q, want %q", got, want)
	}

	keys, ok := byID[iamNodeID("alice", "access-keys")]
	if !ok {
		t.Fatal("no alice access-keys node")
	}
	if keys.ControlFamily != "IA" || len(keys.Controls) != 1 || keys.Controls[0] != (ir.Control{Family: "IA", Base: 5}) {
		t.Errorf("alice access-keys control = %+v/%+v, want IA/IA-5 (base)", keys.ControlFamily, keys.Controls)
	}
	wantAliceAge := ageDaysFromFixture(t, "2025-01-01T00:00:00Z")
	if got := keys.Attributes["oldest_active_key_age_days"]; got != wantAliceAge {
		t.Errorf("alice oldest_active_key_age_days = %q, want %q", got, wantAliceAge)
	}

	// bob has one active key (2025-06-01) and one inactive key created
	// much earlier (2020-01-01). The age reported must be the active
	// key's - an inactive key cannot authenticate, so its age says
	// nothing about rotation posture.
	bobKeys, ok := byID[iamNodeID("bob", "access-keys")]
	if !ok {
		t.Fatal("no bob access-keys node")
	}
	if got, want := bobKeys.Attributes["access_key_count"], "2"; got != want {
		t.Errorf("bob access_key_count = %q, want %q", got, want)
	}
	if got, want := bobKeys.Attributes["active_access_key_count"], "1"; got != want {
		t.Errorf("bob active_access_key_count = %q, want %q", got, want)
	}
	wantBobAge := ageDaysFromFixture(t, "2025-06-01T00:00:00Z")
	if got := bobKeys.Attributes["oldest_active_key_age_days"]; got != wantBobAge {
		t.Errorf("bob oldest_active_key_age_days = %q, want %q (the ACTIVE key's age, not the older inactive one's)", got, wantBobAge)
	}

	// dave has no access keys at all. That is a real resolved
	// measurement, but there is no active key whose age could be
	// reported - recording "0" days would read as "rotated today,"
	// the opposite of the truth.
	daveKeys, ok := byID[iamNodeID("dave", "access-keys")]
	if !ok {
		t.Fatal("no dave access-keys node - zero keys is still a resolved measurement")
	}
	if got, want := daveKeys.Attributes["access_key_count"], "0"; got != want {
		t.Errorf("dave access_key_count = %q, want %q", got, want)
	}
	if got, ok := daveKeys.Attributes["oldest_active_key_age_days"]; ok {
		t.Errorf("dave oldest_active_key_age_days = %q, want the attribute absent entirely (no active key to age)", got)
	}

	// carol's MFA and access-key calls both failed, so neither fact was
	// resolved and neither may appear in the evidence graph.
	if _, ok := byID[iamNodeID("carol", "mfa-devices")]; ok {
		t.Error("carol has an mfa-devices node, want none (the API call failed - unresolved, never guessed)")
	}
	if _, ok := byID[iamNodeID("carol", "access-keys")]; ok {
		t.Error("carol has an access-keys node, want none (the API call failed - unresolved, never guessed)")
	}
}

// TestIAMToIRDoesNotMapConsolePassword pins the deliberate gap
// IAMToIR's doc comment describes: console-password state is collected
// but has no reviewed control assignment yet, so it must not reach the
// evidence graph. If someone later maps it, this test should be updated
// deliberately alongside that decision, not deleted to make it pass.
func TestIAMToIRDoesNotMapConsolePassword(t *testing.T) {
	client := loadFakeIAM(t)
	graph, err := CollectIAM(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectIAM: %v", err)
	}
	irGraph, err := IAMToIR(graph)
	if err != nil {
		t.Fatalf("IAMToIR: %v", err)
	}
	for _, n := range irGraph.Nodes {
		if n.Kind == "iam_user_console_password" {
			t.Errorf("node %s maps console-password state, which has no reviewed control assignment yet", n.ID)
		}
		for k := range n.Attributes {
			if k == "console_password_enabled" {
				t.Errorf("node %s carries a console_password_enabled attribute, which has no reviewed control assignment yet", n.ID)
			}
		}
	}
}

// ageDaysFromFixture computes the whole-day age a key created at
// createdRFC3339 should report as of testObservedAt, so these
// expectations track the fixture dates rather than hardcoding a number
// that silently goes stale if testObservedAt ever moves.
func ageDaysFromFixture(t *testing.T, createdRFC3339 string) string {
	t.Helper()
	created, err := time.Parse(time.RFC3339, createdRFC3339)
	if err != nil {
		t.Fatalf("parse fixture date %q: %v", createdRFC3339, err)
	}
	return strconv.Itoa(int(testObservedAt.Sub(created).Hours() / 24))
}
