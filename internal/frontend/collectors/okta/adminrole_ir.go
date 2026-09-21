package okta

import (
	"strconv"
	"strings"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// adminRolePrivilegedAccounts is the control assignment for an Okta
// user's assigned admin role set: AC-6(5) (Privileged Accounts), not
// the base control. As with AC-2(4) for provisioning events, this is
// not a guess about something uncollectable - AC-6(5)'s own definition
// is "restrict privileged accounts... to a defined subset of authorized
// individuals," and a per-user admin role list IS the evidence of that
// restriction (or its absence). Confirmed against the vendored FedRAMP
// dataset: ac-6.5 is cited by KSI-IAM-JIT and KSI-IAM-SNU. Proposed and
// approved 2026-09-21 alongside this collector's first implementation.
var adminRolePrivilegedAccounts = ir.Control{Family: "AC", Base: 6, Enhancement: 5}

// AdminRoleAssignmentsToIR converts g's users into IR nodes, one per
// resolved user - including a user with zero admin roles, per
// AdminRoleAssignment's own doc comment on why that's a real
// measurement, not nothing to record. A user whose roles could not be
// listed at all (Provenance.Confidence != Deterministic) produces no
// node - the same "never guess" treatment every other mapper in this
// codebase applies.
func AdminRoleAssignmentsToIR(g *AdminRoleAssignmentGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, u := range g.Users {
		if node, ok := mapAdminRoleAssignment(u); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapAdminRoleAssignment records u's role assignment as raw attributes
// (FR-5.9: this mapper records which roles a user holds - and how many -
// never whether that assignment is appropriate; that judgment belongs
// in a backend predicate, not here).
func mapAdminRoleAssignment(u AdminRoleAssignment) (ir.Node, bool) {
	if u.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	return ir.Node{
		ID:            oktaNodeID("admin-role-assignment", u.UserID, "roles"),
		ControlFamily: adminRolePrivilegedAccounts.Family,
		Controls:      []ir.Control{adminRolePrivilegedAccounts},
		Kind:          "okta_admin_role_assignment",
		Attributes: map[string]string{
			"user_login":  u.UserLogin,
			"user_status": u.UserStatus,
			"role_count":  strconv.Itoa(len(u.RoleTypes)),
			"role_types":  strings.Join(u.RoleTypes, ","),
			"role_labels": strings.Join(u.RoleLabels, ","),
		},
		Provenance:    u.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
