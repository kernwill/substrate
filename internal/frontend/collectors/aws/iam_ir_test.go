package aws

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
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

	// alice, bob, dave each resolve all three facts (3 nodes apiece).
	// carol's MFA and access-key calls both error, but her console
	// login profile call resolves to a real "no" (NoSuchEntity, per
	// GetLoginProfile's own documented contract - see
	// collectConsolePassword's doc comment), so she contributes exactly
	// that one node. erin's console call itself errors (simulated
	// throttling, not NoSuchEntity), so she contributes her two
	// resolved facts (MFA, access keys) but no console node.
	// 3+3+1+3+2 = 12.
	if len(irGraph.Nodes) != 12 {
		t.Fatalf("got %d nodes, want 12", len(irGraph.Nodes))
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

	aliceConsole, ok := byID[iamNodeID("alice", "console-password")]
	if !ok {
		t.Fatal("no alice console-password node")
	}
	if aliceConsole.ControlFamily != "IA" || len(aliceConsole.Controls) != 1 || aliceConsole.Controls[0] != (ir.Control{Family: "IA", Base: 2}) {
		t.Errorf("alice console-password control = %+v/%+v, want IA/IA-2 (base, same as MFA)", aliceConsole.ControlFamily, aliceConsole.Controls)
	}
	if got, want := aliceConsole.Attributes["console_password_enabled"], "true"; got != want {
		t.Errorf("alice console_password_enabled = %q, want %q", got, want)
	}

	// carol has no MFA or access-key node (both calls failed), but her
	// console login profile call resolved to a real, documented "no" -
	// GetLoginProfile's NoSuchEntity error IS the resolved answer, not
	// an unresolved one (see collectConsolePassword). That resolved
	// "false" must still produce a node even though her other two
	// facts are entirely missing.
	carolConsole, ok := byID[iamNodeID("carol", "console-password")]
	if !ok {
		t.Fatal("no carol console-password node - NoSuchEntity is a resolved 'no', not an unresolved outcome, and must produce a node even though carol's other two facts failed")
	}
	if got, want := carolConsole.Attributes["console_password_enabled"], "false"; got != want {
		t.Errorf("carol console_password_enabled = %q, want %q", got, want)
	}

	// erin's console login profile call itself failed (simulated
	// throttling, not NoSuchEntity - see testdata/iam_login_profiles.json),
	// so unlike carol she must have no console-password node at all,
	// even though her MFA and access-key facts both resolved fine.
	if _, ok := byID[iamNodeID("erin", "console-password")]; ok {
		t.Error("erin has a console-password node, want none (the underlying API call failed with a non-NoSuchEntity error - unresolved, never guessed)")
	}
}

// TestMapUserAccessKeysReportsNegativeAgeWithoutClamping is a
// regression test: mapUserAccessKeys used to seed its running maximum
// age at 0 and only overwrite it when a later key's AgeDays was
// strictly greater, so a single active key with a negative AgeDays
// (clock skew between this host and AWS, or a key created in the same
// instant observedAt was captured) was silently clamped to "0" - read
// as "freshly rotated" - instead of surfacing the actual, anomalous
// negative value.
func TestMapUserAccessKeysReportsNegativeAgeWithoutClamping(t *testing.T) {
	u := IAMUser{
		Name: "skewed",
		AccessKeys: &AccessKeys{
			Keys:       []AccessKey{{Active: true, AgeDays: -5}},
			Provenance: testProvenance(),
		},
	}
	node, ok := mapUserAccessKeys(u)
	if !ok {
		t.Fatal("mapUserAccessKeys: got false, want true")
	}
	if got, want := node.Attributes["oldest_active_key_age_days"], "-5"; got != want {
		t.Errorf("oldest_active_key_age_days = %q, want %q (the real negative age, not clamped to 0)", got, want)
	}
}

func testProvenance() provenance.Record {
	return provenance.Record{
		SourceType:       "aws",
		Locator:          provenance.Locator{API: "iam:ListAccessKeys", Parameters: map[string]string{"user": "skewed"}},
		Timestamp:        testObservedAt,
		CollectorVersion: IAMCollectorVersion,
		Basis:            provenance.Observed,
		Confidence:       provenance.Deterministic,
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
