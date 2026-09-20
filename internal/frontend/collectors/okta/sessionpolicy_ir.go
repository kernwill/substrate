package okta

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// sessionPolicyAC12 is the control assignment for an Okta sign-on
// policy rule's idle timeout, session lifetime, and persistent-cookie
// setting: base AC-12 (Session Termination). Confirmed against the
// vendored FedRAMP dataset (internal/rules/data/fedramp-consolidated-rules.json)
// rather than assumed: ac-12 is cited by KSI-CNA-ULN and KSI-IAM-ELP;
// ac-11 (Session Lock) is cited by no KSI indicator at all, so it was
// not chosen even though it's a plausible-sounding alternative. Base
// control, no enhancement: the dataset cites no ac-12 enhancement
// anywhere this collector's facts would support. Proposed and approved
// 2026-09-20 alongside this collector's first implementation.
var sessionPolicyAC12 = ir.Control{Family: "AC", Base: 12}

// SessionPolicyToIR converts g's rules into IR nodes, one per resolved
// (policy, rule) pair. A rule whose Actions this collector could not
// parse, or a policy whose rules could not be listed at all
// (Provenance.Confidence != Deterministic either way), produces no node -
// the same "never guess" treatment every other mapper in this codebase
// applies.
func SessionPolicyToIR(g *SessionPolicyGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, r := range g.Rules {
		if node, ok := mapSessionPolicyRule(r); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapSessionPolicyRule records r's session settings as raw attributes
// (FR-5.9's measurement-not-verdict split: this mapper records what the
// idle timeout and session lifetime ARE, never whether those minutes
// satisfy any particular threshold - that judgment belongs in a backend
// predicate, not here).
func mapSessionPolicyRule(r SessionPolicyRule) (ir.Node, bool) {
	if r.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	return ir.Node{
		ID:            oktaNodeID("session-policy", r.PolicyID+"/"+r.RuleID, "session-termination"),
		ControlFamily: sessionPolicyAC12.Family,
		Controls:      []ir.Control{sessionPolicyAC12},
		Kind:          "okta_session_policy_rule",
		Attributes: map[string]string{
			"policy_name":                  r.PolicyName,
			"policy_status":                r.PolicyStatus,
			"rule_name":                    r.RuleName,
			"rule_status":                  r.RuleStatus,
			"max_session_idle_minutes":     strconv.Itoa(r.MaxSessionIdleMinutes),
			"max_session_lifetime_minutes": strconv.Itoa(r.MaxSessionLifetimeMinutes),
			"use_persistent_cookie":        strconv.FormatBool(r.UsePersistentCookie),
		},
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
