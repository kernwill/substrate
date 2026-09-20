package okta

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestMFAEnrollmentToIR(t *testing.T) {
	client := loadFakePolicyEndpoint(t, mfaPolicyType, "mfa_policies.json")
	graph, err := CollectMFAEnrollmentPolicies(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectMFAEnrollmentPolicies: %v", err)
	}
	irGraph, err := MFAEnrollmentToIR(graph)
	if err != nil {
		t.Fatalf("MFAEnrollmentToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// alpha and beta resolved -> 2 nodes; gamma's settings never parsed
	// -> 0 nodes for it.
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (alpha, beta; gamma unresolved)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	alphaID := oktaNodeID("mfa-enrollment-policy", "policy-alpha", "enrollment")
	alpha, ok := byID[alphaID]
	if !ok {
		t.Fatal("no policy-alpha node")
	}
	if alpha.ControlFamily != "IA" || len(alpha.Controls) != 1 || alpha.Controls[0] != (ir.Control{Family: "IA", Base: 2}) {
		t.Errorf("policy-alpha control = %+v/%+v, want IA/IA-2", alpha.ControlFamily, alpha.Controls)
	}
	if alpha.Kind != "okta_mfa_enrollment_policy" {
		t.Errorf("policy-alpha.Kind = %q, want okta_mfa_enrollment_policy", alpha.Kind)
	}
	wantAttrs := map[string]string{
		"policy_name":               "Default MFA Enrollment Policy",
		"policy_status":             "ACTIVE",
		"policy_priority":           "1",
		"factor_okta_verify_enroll": "REQUIRED",
		"factor_okta_otp_enroll":    "OPTIONAL",
		"factor_google_otp_enroll":  "NOT_ALLOWED",
	}
	for k, want := range wantAttrs {
		if got := alpha.Attributes[k]; got != want {
			t.Errorf("policy-alpha attribute %s = %q, want %q", k, got, want)
		}
	}
	if alpha.Provenance.Basis != "observed" {
		t.Errorf("policy-alpha Provenance.Basis = %q, want observed", alpha.Provenance.Basis)
	}

	betaID := oktaNodeID("mfa-enrollment-policy", "policy-beta", "enrollment")
	beta, ok := byID[betaID]
	if !ok {
		t.Fatal("no policy-beta node - an INACTIVE-but-resolved policy must still produce a node")
	}
	if got, want := beta.Attributes["policy_status"], "INACTIVE"; got != want {
		t.Errorf("policy-beta policy_status = %q, want %q", got, want)
	}

	gammaID := oktaNodeID("mfa-enrollment-policy", "policy-gamma", "enrollment")
	if _, ok := byID[gammaID]; ok {
		t.Error("policy-gamma has a node, want none (settings never resolved)")
	}
}
