package okta

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// mfaEnrollmentIA2 is the control assignment for an Okta MFA enrollment
// policy's per-factor enrollment requirement: base IA-2, the same
// control and the same reasoning as AWS IAM's per-user MFA node
// (iamUserMFA, internal/frontend/collectors/aws/iam_ir.go). This
// collector cannot determine whether a given policy is scoped to
// privileged accounts specifically - that would require resolving which
// Okta group counts as "the" privileged group for an arbitrary customer
// org, an unresolved judgment call, not a fact this collector can
// honestly assert - so base IA-2 rather than IA-2(1)/(2) is the honest
// assignment, not a guessed-at enhancement. Proposed and approved
// 2026-09-20 alongside this collector's first implementation.
var mfaEnrollmentIA2 = ir.Control{Family: "IA", Base: 2}

// MFAEnrollmentToIR converts g's policies into IR nodes, one per
// resolved policy. A policy whose Settings this collector could not
// parse (Provenance.Confidence != Deterministic) produces no node - the
// same "never guess" treatment every other mapper in this codebase
// applies.
func MFAEnrollmentToIR(g *MFAEnrollmentGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, p := range g.Policies {
		if node, ok := mapMFAEnrollmentPolicy(p); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapMFAEnrollmentPolicy records p's per-factor enrollment requirement
// as raw attributes (FR-5.9's measurement-not-verdict split: this
// mapper records what each factor's enrollment setting IS, never
// whether that combination counts as "MFA enforced" - that judgment
// belongs in a backend predicate, not here). Attribute keys are
// "factor_<type>_enroll", one per factor Okta's policy names - dynamic
// per policy, since which factor types exist varies by org
// configuration, the same "collect the real shape, don't force a fixed
// schema" treatment aws.mapUserAccessKeys' dynamic
// oldest_active_key_age_days presence already established for this
// codebase.
func mapMFAEnrollmentPolicy(p MFAEnrollmentPolicy) (ir.Node, bool) {
	if p.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	attrs := map[string]string{
		"policy_name":     p.Name,
		"policy_status":   p.Status,
		"policy_priority": strconv.Itoa(p.Priority),
	}
	for factorType, enroll := range p.Factors {
		attrs["factor_"+factorType+"_enroll"] = enroll
	}

	return ir.Node{
		ID:            oktaNodeID("mfa-enrollment-policy", p.ID, "enrollment"),
		ControlFamily: mfaEnrollmentIA2.Family,
		Controls:      []ir.Control{mfaEnrollmentIA2},
		Kind:          "okta_mfa_enrollment_policy",
		Attributes:    attrs,
		Provenance:    p.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
