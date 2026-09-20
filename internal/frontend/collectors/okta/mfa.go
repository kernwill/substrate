package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

// MFACollectorVersion is this file's own collector version (FR-4.1),
// independent of every other collector version in this package.
const MFACollectorVersion = "okta-mfa/v0.1.0"

// mfaPolicyType is the Okta policy type this collector requests -
// MFA_ENROLL, per FR-3.9's "MFA enforcement."
const mfaPolicyType = "MFA_ENROLL"

// MFAEnrollmentPolicy is one collected Okta MFA enrollment policy.
// Factors is never nil when Provenance.Confidence is Deterministic -
// see aws.Bucket's doc comment for why this package always records a
// fact, resolved or not, rather than dropping a policy it couldn't
// parse.
type MFAEnrollmentPolicy struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Priority int    `json:"priority"`
	// Factors maps an Okta factor type (e.g. "okta_verify", "okta_otp")
	// to its enrollment requirement exactly as the API returned it
	// ("REQUIRED", "OPTIONAL", "NOT_ALLOWED", or any other value Okta
	// documents) - this collector never interprets or normalizes the
	// value; that is a backend predicate's job, not a frontend
	// collector's (FR-5.9).
	Factors    map[string]string `json:"factors"`
	Provenance provenance.Record `json:"provenance"`
}

// MFAEnrollmentGraph is every MFA enrollment policy found in the
// caller's Okta org.
type MFAEnrollmentGraph struct {
	Policies []MFAEnrollmentPolicy `json:"policies"`
}

// mfaSettings is the shape of RawPolicy.Settings for an MFA_ENROLL
// policy - only the "factors" key, since that's all FR-3.9's "MFA
// enforcement" needs from this policy type.
type mfaSettings struct {
	Factors map[string]struct {
		Enroll struct {
			Self string `json:"self"`
		} `json:"enroll"`
	} `json:"factors"`
}

// CollectMFAEnrollmentPolicies fetches every MFA enrollment policy in
// the caller's Okta org - a single org-wide call (client.ListPolicies) -
// then parses each policy's Settings independently, so one policy's
// malformed Settings doesn't take down the whole collection run.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp,
// never derived from time.Now() here - matching aws.CollectS3's own
// convention, for the same reproducibility reason (FR-5.3).
func CollectMFAEnrollmentPolicies(ctx context.Context, client OktaAPI, observedAt time.Time) (*MFAEnrollmentGraph, error) {
	raw, err := client.ListPolicies(ctx, mfaPolicyType)
	if err != nil {
		return nil, fmt.Errorf("okta: mfa: list policies: %w", err)
	}

	policies := make([]MFAEnrollmentPolicy, 0, len(raw))
	for _, p := range raw {
		policies = append(policies, parseMFAPolicy(p, observedAt))
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })

	return &MFAEnrollmentGraph{Policies: policies}, nil
}

func parseMFAPolicy(p RawPolicy, observedAt time.Time) MFAEnrollmentPolicy {
	const api = "okta:ListPolicies:MFA_ENROLL"
	base := MFAEnrollmentPolicy{ID: p.ID, Name: p.Name, Status: p.Status, Priority: p.Priority}

	var settings mfaSettings
	if err := json.Unmarshal(p.Settings, &settings); err != nil {
		base.Provenance = mfaUnresolvedRecord(p.ID, api, fmt.Sprintf("parsing policy settings: %v", err), observedAt)
		return base
	}

	factors := make(map[string]string, len(settings.Factors))
	for factorType, f := range settings.Factors {
		factors[factorType] = f.Enroll.Self
	}
	base.Factors = factors
	base.Provenance = mfaRecord(p.ID, api, observedAt)
	return base
}

// mfaRecord and mfaUnresolvedRecord are thin wrappers around this
// package's shared observedRecord/unresolvedRecord (provenance.go),
// fixing this file's own collector version and locator parameter key -
// same pattern as aws's per-collector wrapper functions (e.g.
// cloudTrailRecord).
func mfaRecord(policyID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(MFACollectorVersion, api, map[string]string{"policy_id": policyID}, observedAt)
}

func mfaUnresolvedRecord(policyID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(MFACollectorVersion, api, reason, map[string]string{"policy_id": policyID}, observedAt)
}
