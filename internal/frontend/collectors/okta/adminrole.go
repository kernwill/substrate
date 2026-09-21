package okta

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

// AdminRoleCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const AdminRoleCollectorVersion = "okta-admin-role/v0.1.0"

// AdminRoleAssignment is one collected Okta user's assigned admin
// roles. RoleTypes/RoleLabels are never nil when Provenance.Confidence
// is Deterministic, even when the user holds zero admin roles - a
// resolved zero is a real measurement, not an absence: see
// aws.mapUserMFA's own doc comment for why "no privileged role
// assigned" must produce a node exactly like "one role assigned" does,
// not be treated as nothing to record.
type AdminRoleAssignment struct {
	UserID     string   `json:"user_id"`
	UserLogin  string   `json:"user_login"`
	UserStatus string   `json:"user_status"`
	RoleTypes  []string `json:"role_types"`
	RoleLabels []string `json:"role_labels"`

	Provenance provenance.Record `json:"provenance"`
}

// AdminRoleAssignmentGraph is every user found in the caller's Okta org,
// each with their assigned admin roles (possibly none).
type AdminRoleAssignmentGraph struct {
	Users []AdminRoleAssignment `json:"users"`
}

// CollectAdminRoleAssignments enumerates every user in the caller's
// Okta org (client.ListUsers), then fans out one call per user for
// their assigned admin roles (client.ListUserRoles), up to
// maxConcurrentItems at a time - the same shape aws.CollectIAM uses for
// per-user AWS facts.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp,
// never derived from time.Now() here - matching every other collector
// in this codebase, for the same reproducibility reason (FR-5.3).
func CollectAdminRoleAssignments(ctx context.Context, client OktaAPI, observedAt time.Time) (*AdminRoleAssignmentGraph, error) {
	rawUsers, err := client.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: admin-role: list users: %w", err)
	}

	byID := make(map[string]RawUser, len(rawUsers))
	ids := make([]string, len(rawUsers))
	for i, u := range rawUsers {
		byID[u.ID] = u
		ids[i] = u.ID
	}
	sort.Strings(ids)

	users, err := collectConcurrent(ctx, ids, func(ctx context.Context, userID string) AdminRoleAssignment {
		return collectUserAdminRoles(ctx, client, byID[userID], observedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("okta: admin-role: collect user roles: %w", err)
	}

	return &AdminRoleAssignmentGraph{Users: users}, nil
}

func collectUserAdminRoles(ctx context.Context, client OktaAPI, u RawUser, observedAt time.Time) AdminRoleAssignment {
	const api = "okta:ListUserRoles"
	base := AdminRoleAssignment{UserID: u.ID, UserLogin: u.Profile.Login, UserStatus: u.Status}

	rawRoles, err := client.ListUserRoles(ctx, u.ID)
	if err != nil {
		base.Provenance = adminRoleUnresolvedRecord(u.ID, api, err.Error(), observedAt)
		return base
	}

	types := make([]string, len(rawRoles))
	labels := make([]string, len(rawRoles))
	for i, r := range rawRoles {
		types[i] = r.Type
		labels[i] = r.Label
	}
	base.RoleTypes = types
	base.RoleLabels = labels
	base.Provenance = adminRoleRecord(u.ID, api, observedAt)
	return base
}

// adminRoleRecord and adminRoleUnresolvedRecord are thin wrappers
// around this package's shared observedRecord/unresolvedRecord
// (provenance.go), fixing this file's own collector version - same
// pattern as mfaRecord/mfaUnresolvedRecord (mfa.go).
func adminRoleRecord(userID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(AdminRoleCollectorVersion, api, map[string]string{"user_id": userID}, observedAt)
}

func adminRoleUnresolvedRecord(userID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(AdminRoleCollectorVersion, api, reason, map[string]string{"user_id": userID}, observedAt)
}
