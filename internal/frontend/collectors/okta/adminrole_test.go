package okta

import (
	"context"
	"errors"
	"testing"

	"github.com/kernwill/substrate/internal/provenance"
)

func TestCollectAdminRoleAssignments(t *testing.T) {
	client := newFakePolicyEndpoint().
		withUsers(t, "admin_role_users.json").
		withUserRoles(t, "user-alpha", "admin_roles_alpha.json").
		withUserRoles(t, "user-beta", "admin_roles_beta.json").
		withUserRolesError("user-gamma", errors.New("simulated ListUserRoles failure"))

	graph, err := CollectAdminRoleAssignments(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectAdminRoleAssignments: %v", err)
	}
	if len(graph.Users) != 3 {
		t.Fatalf("got %d users, want 3", len(graph.Users))
	}

	byID := make(map[string]AdminRoleAssignment, len(graph.Users))
	for _, u := range graph.Users {
		byID[u.UserID] = u
	}

	alpha := byID["user-alpha"]
	if alpha.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("user-alpha.Provenance.Confidence = %v, want Deterministic", alpha.Provenance.Confidence)
	}
	if len(alpha.RoleTypes) != 1 || alpha.RoleTypes[0] != "SUPER_ADMIN" {
		t.Errorf("user-alpha.RoleTypes = %v, want [SUPER_ADMIN]", alpha.RoleTypes)
	}
	if alpha.UserLogin != "alpha@example.com" {
		t.Errorf("user-alpha.UserLogin = %q, want alpha@example.com", alpha.UserLogin)
	}

	beta := byID["user-beta"]
	if beta.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("user-beta.Provenance.Confidence = %v, want Deterministic", beta.Provenance.Confidence)
	}
	if len(beta.RoleTypes) != 0 {
		t.Errorf("user-beta.RoleTypes = %v, want empty (a resolved zero, not an absence)", beta.RoleTypes)
	}

	gamma := byID["user-gamma"]
	if gamma.Provenance.Confidence != provenance.Unresolved {
		t.Fatalf("user-gamma.Provenance.Confidence = %v, want Unresolved (ListUserRoles failed)", gamma.Provenance.Confidence)
	}
	if gamma.Provenance.UnresolvedReason == "" {
		t.Error("user-gamma.Provenance.UnresolvedReason is empty")
	}
}

func TestCollectAdminRoleAssignmentsPropagatesListUsersError(t *testing.T) {
	client := newFakePolicyEndpoint().withUsersError(errors.New("simulated ListUsers failure"))
	if _, err := CollectAdminRoleAssignments(context.Background(), client, testObservedAt); err == nil {
		t.Fatal("CollectAdminRoleAssignments succeeded, want an error when ListUsers fails")
	}
}
