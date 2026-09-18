package aws

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestCloudTrailToIR(t *testing.T) {
	client := loadFakeCloudTrail(t)
	graph, err := CollectCloudTrail(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectCloudTrail: %v", err)
	}
	irGraph, err := CloudTrailToIR(graph)
	if err != nil {
		t.Fatalf("CloudTrailToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	// alpha: config and logging both resolved -> 2 nodes.
	// beta: config and logging both resolved -> 2 nodes.
	// delta: config unresolved, logging resolved -> 0 nodes (audit
	// record generation needs config; log file validation needs config
	// too - neither can go through on logging alone).
	// gamma: config resolved, logging unresolved -> 1 node (log file
	// validation only, since it doesn't need Logging at all).
	if len(irGraph.Nodes) != 5 {
		t.Fatalf("got %d nodes, want 5 (alpha x2, beta x2, delta x0, gamma x1)", len(irGraph.Nodes))
	}

	auditGen, ok := byID[cloudTrailNodeID("alpha", "audit-record-generation")]
	if !ok {
		t.Fatal("no alpha audit-record-generation node")
	}
	if auditGen.ControlFamily != "AU" || len(auditGen.Controls) != 1 || auditGen.Controls[0] != (ir.Control{Family: "AU", Base: 12}) {
		t.Errorf("alpha audit-record-generation control = %+v/%+v, want AU/AU-12", auditGen.ControlFamily, auditGen.Controls)
	}
	for attr, want := range map[string]string{
		"is_logging":            "true",
		"is_multi_region_trail": "true",
		"is_organization_trail": "true",
	} {
		if got := auditGen.Attributes[attr]; got != want {
			t.Errorf("alpha audit-record-generation %s = %q, want %q", attr, got, want)
		}
	}
	if auditGen.Provenance.Basis != "observed" {
		t.Errorf("alpha audit-record-generation Provenance.Basis = %q, want observed", auditGen.Provenance.Basis)
	}

	logValidation, ok := byID[cloudTrailNodeID("alpha", "log-file-validation")]
	if !ok {
		t.Fatal("no alpha log-file-validation node")
	}
	if logValidation.ControlFamily != "AU" || len(logValidation.Controls) != 1 || logValidation.Controls[0] != (ir.Control{Family: "AU", Base: 9}) {
		t.Errorf("alpha log-file-validation control = %+v/%+v, want AU/AU-9", logValidation.ControlFamily, logValidation.Controls)
	}
	if got, want := logValidation.Attributes["log_file_validation_enabled"], "true"; got != want {
		t.Errorf("alpha log_file_validation_enabled = %q, want %q", got, want)
	}

	// beta: a resolved FALSE on every flag is a real measurement, not an
	// absence - it must still produce both nodes.
	betaAuditGen, ok := byID[cloudTrailNodeID("beta", "audit-record-generation")]
	if !ok {
		t.Fatal("no beta audit-record-generation node - a resolved false must still produce a node")
	}
	if got, want := betaAuditGen.Attributes["is_logging"], "false"; got != want {
		t.Errorf("beta is_logging = %q, want %q", got, want)
	}
	if _, ok := byID[cloudTrailNodeID("beta", "log-file-validation")]; !ok {
		t.Error("no beta log-file-validation node - a resolved false must still produce a node")
	}

	// delta's config never resolved (an incomplete DescribeTrails
	// response), so neither node may exist even though its logging
	// status resolved fine.
	if _, ok := byID[cloudTrailNodeID("delta", "audit-record-generation")]; ok {
		t.Error("delta has an audit-record-generation node, want none (config unresolved)")
	}
	if _, ok := byID[cloudTrailNodeID("delta", "log-file-validation")]; ok {
		t.Error("delta has a log-file-validation node, want none (config unresolved)")
	}

	// gamma's logging status failed to resolve, so audit-record-generation
	// (which needs both config AND logging) must be absent, but
	// log-file-validation (config only) must still be present.
	if _, ok := byID[cloudTrailNodeID("gamma", "audit-record-generation")]; ok {
		t.Error("gamma has an audit-record-generation node, want none (logging status unresolved)")
	}
	if _, ok := byID[cloudTrailNodeID("gamma", "log-file-validation")]; !ok {
		t.Error("gamma has no log-file-validation node, want one (config resolved independently of the logging-status failure)")
	}
}
