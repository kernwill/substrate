package okta

import (
	"context"
	"errors"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestAdminRoleAssignmentsToIR(t *testing.T) {
	client := newFakePolicyEndpoint().
		withUsers(t, "admin_role_users.json").
		withUserRoles(t, "user-alpha", "admin_roles_alpha.json").
		withUserRoles(t, "user-beta", "admin_roles_beta.json").
		withUserRolesError("user-gamma", errors.New("simulated ListUserRoles failure"))

	graph, err := CollectAdminRoleAssignments(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectAdminRoleAssignments: %v", err)
	}
	irGraph, err := AdminRoleAssignmentsToIR(graph)
	if err != nil {
		t.Fatalf("AdminRoleAssignmentsToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// alpha and beta resolved -> 2 nodes; gamma's roles never resolved
	// -> 0 nodes for it.
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (alpha, beta; gamma unresolved)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	alphaID := oktaNodeID("admin-role-assignment", "user-alpha", "roles")
	alpha, ok := byID[alphaID]
	if !ok {
		t.Fatal("no user-alpha node")
	}
	if alpha.ControlFamily != "AC" || len(alpha.Controls) != 1 || alpha.Controls[0] != (ir.Control{Family: "AC", Base: 6, Enhancement: 5}) {
		t.Errorf("user-alpha control = %+v/%+v, want AC/AC-6(5)", alpha.ControlFamily, alpha.Controls)
	}
	if alpha.Kind != "okta_admin_role_assignment" {
		t.Errorf("user-alpha.Kind = %q, want okta_admin_role_assignment", alpha.Kind)
	}
	if got, want := alpha.Attributes["role_count"], "1"; got != want {
		t.Errorf("user-alpha role_count = %q, want %q", got, want)
	}
	if got, want := alpha.Attributes["role_types"], "SUPER_ADMIN"; got != want {
		t.Errorf("user-alpha role_types = %q, want %q", got, want)
	}
	if alpha.Provenance.Basis != "observed" {
		t.Errorf("user-alpha Provenance.Basis = %q, want observed", alpha.Provenance.Basis)
	}

	betaID := oktaNodeID("admin-role-assignment", "user-beta", "roles")
	beta, ok := byID[betaID]
	if !ok {
		t.Fatal("no user-beta node - a zero-role user must still produce a node")
	}
	if got, want := beta.Attributes["role_count"], "0"; got != want {
		t.Errorf("user-beta role_count = %q, want %q", got, want)
	}

	gammaID := oktaNodeID("admin-role-assignment", "user-gamma", "roles")
	if _, ok := byID[gammaID]; ok {
		t.Error("user-gamma has a node, want none (roles never resolved)")
	}
}
