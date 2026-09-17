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

// IAMToIR converts g's users into IR nodes.
//
// Two of the three collected facts are mapped, both to human-reviewed
// control assignments (see iamUserMFA and iamUserAccessKeys above):
// MFA device enrollment and access-key inventory/age. A user whose
// corresponding fact could not be resolved (Provenance.Confidence !=
// Deterministic - see iam.go for why an API failure is recorded rather
// than dropped) produces no node for it, the same "never guess"
// treatment every other mapper in this codebase applies.
//
// IAMUser.ConsolePassword is deliberately NOT mapped yet. Whether a
// user has a console login profile is plainly an IA-family fact, and
// pairing it with MFA enrollment is exactly what a backend predicate
// would need to judge "this user can log in interactively but has no
// second factor" - but which control it maps to has not been reviewed,
// and this file does not decide that unilaterally (the same treatment
// S3 access logging gets in ir.go). The practical consequence, worth
// knowing before trusting IA-2 coverage: a backend today sees the MFA
// device count alone and cannot yet condition on whether the user even
// has console access to protect.
func IAMToIR(g *IAMGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, u := range g.Users {
		if node, ok := mapUserMFA(u); ok {
			out.Nodes = append(out.Nodes, node)
		}
		if node, ok := mapUserAccessKeys(u); ok {
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

	activeCount, oldestActiveAge := 0, 0
	for _, k := range u.AccessKeys.Keys {
		if !k.Active {
			continue
		}
		activeCount++
		if k.AgeDays > oldestActiveAge {
			oldestActiveAge = k.AgeDays
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
