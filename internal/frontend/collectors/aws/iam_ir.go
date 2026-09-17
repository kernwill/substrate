package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// iamUserMFA is the control assignment for how many MFA devices an IAM
// user has enrolled: base IA-2 (Identification and Authentication,
// Organizational Users), whose own CTL guidance in the vendored dataset
// is specifically about multi-factor authentication ("Multi-factor
// authentication must be phishing-resistant. In accordance with current
// CISA Guidance.").
//
// Deliberately the BASE control, not IA-2(1) or IA-2(2): those two
// enhancements split on privileged versus non-privileged accounts, and
// this collector cannot tell those apart - it does not read role or
// policy attachment at all (see IAMUser's own doc comment on that
// scoping). Mapping to an enhancement would assert a privilege-level
// judgment no collected fact here supports.
//
// Local to this file rather than internal/frontend/controls: that
// package is for assignments two collectors genuinely share (see its
// doc comment), and nothing else evidences IA-2 today.
var iamUserMFA = ir.Control{Family: "IA", Base: 2}

// iamUserAccessKeys is the control assignment for an IAM user's access
// keys and their ages: base IA-5 (Authenticator Management). An access
// key is functionally a long-lived authenticator, and its age is the
// measurement a rotation requirement is asserted against.
//
// Base control, no enhancement: the vendored dataset's IA-5 guidance is
// about authenticator strength and assertion encryption (NIST Digital
// Identity Guidelines IAL/AAL/FAL levels), and does not name key
// rotation or key age specifically - so no enhancement is a confirmed
// fit, and the base control is the honest assignment rather than a
// guessed-at one.
var iamUserAccessKeys = ir.Control{Family: "IA", Base: 5}

// iamUserConsolePassword is the control assignment for whether an IAM
// user has a console login profile at all: base IA-2, the same control
// as iamUserMFA above, not IA-5. Reviewed and decided deliberately: a
// console password is the base authentication mechanism IA-2's own
// MFA-requiring enhancements (IA-2(1)/(2)) layer a second factor on top
// of, so "does this user have an interactive login surface" and "does
// this user have MFA enrolled" are one IA-2 story, not two stories in
// different control families a backend predicate would otherwise need
// to correlate across.
//
// Kept as its OWN node (mapUserConsolePassword), not folded into
// mapUserMFA's node, even though both share this same control: the two
// facts come from independent API calls (GetLoginProfile vs
// ListMFADevices) with independent resolution outcomes, and ir.Node has
// exactly one Provenance field. Merging them would force either
// dropping a resolved fact because the other call failed, or fabricating
// a shared provenance that doesn't truly describe both - both wrong.
// Keeping them separate costs nothing: a backend rule that needs both
// facts for the same user already has a join key with no new mechanism
// required, since both nodes' Provenance.Locator.Parameters carry the
// same "user" value (observedRecord's own existing shape - see
// provenance.go).
var iamUserConsolePassword = ir.Control{Family: "IA", Base: 2}

// IAMToIR converts g's users into IR nodes: MFA device enrollment,
// access-key inventory/age, and console login profile existence, each
// mapped to a human-reviewed control assignment (see iamUserMFA,
// iamUserAccessKeys, and iamUserConsolePassword above). A user whose
// corresponding fact could not be resolved (Provenance.Confidence !=
// Deterministic - see iam.go for why an API failure is recorded rather
// than dropped) produces no node for it, the same "never guess"
// treatment every other mapper in this codebase applies.
func IAMToIR(g *IAMGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, u := range g.Users {
		if node, ok := mapUserMFA(u); ok {
			out.Nodes = append(out.Nodes, node)
		}
		if node, ok := mapUserAccessKeys(u); ok {
			out.Nodes = append(out.Nodes, node)
		}
		if node, ok := mapUserConsolePassword(u); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

func iamNodeID(user, aspect string) ir.NodeID {
	return awsNodeID("iam", user, aspect)
}

// mapUserMFA records how many MFA devices u has enrolled. Zero is a
// real, resolved measurement, not an absence - a user with no MFA
// device is exactly the case a backend predicate over IA-2 exists to
// catch, so it must produce a node rather than silence (FR-5.9's
// measurement-not-verdict split: this file records the count, and
// never decides whether that count is acceptable).
func mapUserMFA(u IAMUser) (ir.Node, bool) {
	if u.MFADevices == nil || u.MFADevices.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	return ir.Node{
		ID:            iamNodeID(u.Name, "mfa-devices"),
		ControlFamily: iamUserMFA.Family,
		Controls:      []ir.Control{iamUserMFA},
		Kind:          "iam_user_mfa_devices",
		Attributes:    map[string]string{"mfa_device_count": strconv.Itoa(u.MFADevices.Count)},
		Provenance:    u.MFADevices.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// mapUserAccessKeys records u's access-key inventory and the age of its
// oldest ACTIVE key, which is the measurement a key-rotation
// requirement is actually asserted against - an inactive key cannot be
// used to authenticate, so its age says nothing about rotation posture.
//
// oldest_active_key_age_days is omitted entirely when u has no active
// keys, rather than recorded as "0": zero days would read as "a key was
// rotated today," the opposite of "there is no active key here at all."
// active_key_count is what distinguishes those two cases, and it is
// always present.
func mapUserAccessKeys(u IAMUser) (ir.Node, bool) {
	if u.AccessKeys == nil || u.AccessKeys.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	// oldestActiveAge tracks the maximum AgeDays seen so far, but is not
	// seeded at 0: 0 is a real, meaningful AgeDays value (a key rotated
	// today), and seeding the running maximum there silently clamped a
	// negative AgeDays - which can happen under clock skew between this
	// host and AWS, or a key created in the same instant observedAt was
	// captured - to "0", reading as "freshly rotated" instead of
	// surfacing the actual anomalous value. sawActive tracks whether
	// oldestActiveAge has been set from a real key yet, so the first
	// active key encountered is taken unconditionally rather than
	// compared against an assumed floor.
	activeCount, oldestActiveAge := 0, 0
	sawActive := false
	for _, k := range u.AccessKeys.Keys {
		if !k.Active {
			continue
		}
		activeCount++
		if !sawActive || k.AgeDays > oldestActiveAge {
			oldestActiveAge = k.AgeDays
			sawActive = true
		}
	}

	attrs := map[string]string{
		"access_key_count":        strconv.Itoa(len(u.AccessKeys.Keys)),
		"active_access_key_count": strconv.Itoa(activeCount),
	}
	if activeCount > 0 {
		attrs["oldest_active_key_age_days"] = strconv.Itoa(oldestActiveAge)
	}

	return ir.Node{
		ID:            iamNodeID(u.Name, "access-keys"),
		ControlFamily: iamUserAccessKeys.Family,
		Controls:      []ir.Control{iamUserAccessKeys},
		Kind:          "iam_user_access_keys",
		Attributes:    attrs,
		Provenance:    u.AccessKeys.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// mapUserConsolePassword records whether u has a console login profile
// at all. False is a real, resolved measurement, not an absence: it is
// exactly what tells a backend predicate that u.MFADevices.Count == 0
// is irrelevant for this user (no password-based login surface exists
// to protect), rather than a live gap the way it would be for a user
// who does have a console password.
func mapUserConsolePassword(u IAMUser) (ir.Node, bool) {
	if u.ConsolePassword == nil || u.ConsolePassword.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}
	return ir.Node{
		ID:            iamNodeID(u.Name, "console-password"),
		ControlFamily: iamUserConsolePassword.Family,
		Controls:      []ir.Control{iamUserConsolePassword},
		Kind:          "iam_user_console_password",
		Attributes:    map[string]string{"console_password_enabled": strconv.FormatBool(u.ConsolePassword.Enabled)},
		Provenance:    u.ConsolePassword.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
