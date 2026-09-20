package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

// SessionPolicyCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const SessionPolicyCollectorVersion = "okta-session-policy/v0.1.0"

// sessionPolicyType is the Okta policy type this collector requests -
// OKTA_SIGN_ON, the org's global session policy, per FR-3.9's "session
// policy."
const sessionPolicyType = "OKTA_SIGN_ON"

// SessionPolicyRule is one collected Okta sign-on policy rule. Unlike
// MFAEnrollmentPolicy, the fact granularity here is the (policy, rule)
// pair, not the policy alone: idle timeout and session lifetime live on
// each rule (client.go's OktaAPI doc comment explains why), and
// different rules under the same policy can set different values for
// different conditions.
type SessionPolicyRule struct {
	PolicyID     string `json:"policy_id"`
	PolicyName   string `json:"policy_name"`
	PolicyStatus string `json:"policy_status"`
	RuleID       string `json:"rule_id"`
	RuleName     string `json:"rule_name"`
	RuleStatus   string `json:"rule_status"`

	MaxSessionIdleMinutes     int  `json:"max_session_idle_minutes"`
	MaxSessionLifetimeMinutes int  `json:"max_session_lifetime_minutes"`
	UsePersistentCookie       bool `json:"use_persistent_cookie"`

	Provenance provenance.Record `json:"provenance"`
}

// SessionPolicyGraph is every sign-on policy rule found in the caller's
// Okta org.
type SessionPolicyGraph struct {
	Rules []SessionPolicyRule `json:"rules"`
}

// sessionRuleActions is the shape of RawPolicyRule.Actions for an
// OKTA_SIGN_ON policy rule - only the "signon.session" object, since
// that's all FR-3.9's "session policy" needs from this rule type.
type sessionRuleActions struct {
	SignOn struct {
		Session struct {
			MaxSessionIdleMinutes     int  `json:"maxSessionIdleMinutes"`
			MaxSessionLifetimeMinutes int  `json:"maxSessionLifetimeMinutes"`
			UsePersistentCookie       bool `json:"usePersistentCookie"`
		} `json:"session"`
	} `json:"signon"`
}

// CollectSessionPolicies fetches every sign-on policy in the caller's
// Okta org, then - unlike CollectMFAEnrollmentPolicies - fetches each
// policy's rules with a second call (client.ListPolicyRules) and parses
// each rule's session actions independently, so one policy or rule's
// failure doesn't take down the whole collection run.
//
// A policy whose rules could not be listed at all produces one
// Unresolved SessionPolicyRule with no RuleID, recording the failure at
// the policy level rather than silently producing zero rows for it.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp,
// never derived from time.Now() here - matching every other collector
// in this codebase, for the same reproducibility reason (FR-5.3).
func CollectSessionPolicies(ctx context.Context, client OktaAPI, observedAt time.Time) (*SessionPolicyGraph, error) {
	policies, err := client.ListPolicies(ctx, sessionPolicyType)
	if err != nil {
		return nil, fmt.Errorf("okta: session-policy: list policies: %w", err)
	}

	var rules []SessionPolicyRule
	for _, p := range policies {
		rawRules, err := client.ListPolicyRules(ctx, p.ID)
		if err != nil {
			rules = append(rules, SessionPolicyRule{
				PolicyID:     p.ID,
				PolicyName:   p.Name,
				PolicyStatus: p.Status,
				Provenance:   sessionPolicyUnresolvedRecord(p.ID, "", "okta:ListPolicyRules:OKTA_SIGN_ON", err.Error(), observedAt),
			})
			continue
		}
		for _, r := range rawRules {
			rules = append(rules, parseSessionPolicyRule(p, r, observedAt))
		}
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].PolicyID != rules[j].PolicyID {
			return rules[i].PolicyID < rules[j].PolicyID
		}
		return rules[i].RuleID < rules[j].RuleID
	})

	return &SessionPolicyGraph{Rules: rules}, nil
}

func parseSessionPolicyRule(p RawPolicy, r RawPolicyRule, observedAt time.Time) SessionPolicyRule {
	const api = "okta:ListPolicyRules:OKTA_SIGN_ON"
	base := SessionPolicyRule{
		PolicyID:     p.ID,
		PolicyName:   p.Name,
		PolicyStatus: p.Status,
		RuleID:       r.ID,
		RuleName:     r.Name,
		RuleStatus:   r.Status,
	}

	var actions sessionRuleActions
	if err := json.Unmarshal(r.Actions, &actions); err != nil {
		base.Provenance = sessionPolicyUnresolvedRecord(p.ID, r.ID, api, fmt.Sprintf("parsing rule actions: %v", err), observedAt)
		return base
	}

	base.MaxSessionIdleMinutes = actions.SignOn.Session.MaxSessionIdleMinutes
	base.MaxSessionLifetimeMinutes = actions.SignOn.Session.MaxSessionLifetimeMinutes
	base.UsePersistentCookie = actions.SignOn.Session.UsePersistentCookie
	base.Provenance = sessionPolicyRecord(p.ID, r.ID, api, observedAt)
	return base
}

// sessionPolicyRecord and sessionPolicyUnresolvedRecord are thin
// wrappers around this package's shared observedRecord/unresolvedRecord
// (provenance.go), fixing this file's own collector version and both
// locator parameter keys (policy_id and rule_id) - same pattern as
// mfaRecord/mfaUnresolvedRecord (mfa.go).
func sessionPolicyRecord(policyID, ruleID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(SessionPolicyCollectorVersion, api, map[string]string{"policy_id": policyID, "rule_id": ruleID}, observedAt)
}

func sessionPolicyUnresolvedRecord(policyID, ruleID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(SessionPolicyCollectorVersion, api, reason, map[string]string{"policy_id": policyID, "rule_id": ruleID}, observedAt)
}
