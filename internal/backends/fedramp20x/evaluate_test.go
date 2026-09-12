package fedramp20x

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
	"github.com/kernwill/substrate/internal/rules"
)

func loadVendoredDataset(t *testing.T) *rules.Dataset {
	t.Helper()
	ds, err := rules.Default()
	if err != nil {
		t.Fatalf("rules.Default(): %v", err)
	}
	return ds
}

func testProvenance() provenance.Record {
	return provenance.Record{
		SourceType:       "test",
		Locator:          provenance.Locator{Path: "test.tf", Line: 1},
		Timestamp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CollectorVersion: "test",
		Basis:            provenance.Declared,
		Confidence:       provenance.Deterministic,
	}
}

func testNode(id ir.NodeID, family ir.ControlFamily, base int, enhancement int) ir.Node {
	return ir.Node{
		ID:            id,
		ControlFamily: family,
		Controls:      []ir.Control{{Family: family, Base: base, Enhancement: enhancement}},
		Kind:          "test_fact",
		Provenance:    testProvenance(),
		SchemaVersion: ir.SchemaVersion,
	}
}

// TestEvaluateSVCAgainstRealCollectors runs the actual, real evidence
// KSI-SVC's real Rego module produces against exactly what our current
// frontend collectors evidence today: an SC-28(1) node (from Terraform's
// aws_s3_bucket_server_side_encryption_configuration mapping), and
// nothing else. Every KSI-SVC-* indicator references more controls than
// that single one, so every indicator must come back undetermined - this
// asserts the honest state of Phase 1 today, not a hoped-for one.
func TestEvaluateSVCAgainstRealCollectors(t *testing.T) {
	ds := loadVendoredDataset(t)
	g := ir.Graph{Nodes: []ir.Node{
		testNode("terraform:aws_s3_bucket_server_side_encryption_configuration.example", "SC", 28, 1),
	}}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	svcTheme := ds.KSI["SVC"]
	if len(svcTheme.Indicators) == 0 {
		t.Fatal("vendored dataset has no KSI-SVC indicators - test fixture assumption broken")
	}

	got := map[string]IndicatorResult{}
	for _, r := range results {
		if r.Family == "SVC" {
			got[r.Indicator] = r
		}
	}
	if len(got) != len(svcTheme.Indicators) {
		t.Fatalf("got %d SVC results, want one per indicator (%d)", len(got), len(svcTheme.Indicators))
	}
	for name, r := range got {
		if r.Status != StatusUndetermined {
			t.Errorf("%s: status = %q, want %q (only sc-28.1 is evidenced; every KSI-SVC indicator references more controls than that)", name, r.Status, StatusUndetermined)
		}
		if r.Reason == "" {
			t.Errorf("%s: reason is empty", name)
		}
	}

	// KSI-SVC-SIN references sc-28.1 among many others - confirm it's
	// specifically the "some but not all" branch, not "none at all",
	// given the one node we fed in.
	sin, ok := got["KSI-SVC-SIN"]
	if !ok {
		t.Fatal("KSI-SVC-SIN missing from results")
	}
	if sin.RemediationHint == "" {
		t.Error("KSI-SVC-SIN: remediation_hint is empty")
	}
}

// TestEvaluateSVCFullCoverageSatisfied proves the "satisfied" branch is
// real, not merely unreachable code: given synthetic evidence for every
// control KSI-SVC-SIN references, it comes back satisfied with evidence
// pointing at the nodes that back it.
func TestEvaluateSVCFullCoverageSatisfied(t *testing.T) {
	ds := loadVendoredDataset(t)
	sin, ok := ds.KSI["SVC"].Indicators["KSI-SVC-SIN"]
	if !ok {
		t.Fatal("KSI-SVC-SIN not found in vendored dataset - test fixture assumption broken")
	}
	controlIDs, err := sin.ControlIDs()
	if err != nil {
		t.Fatalf("KSI-SVC-SIN.ControlIDs(): %v", err)
	}
	if len(controlIDs) == 0 {
		t.Fatal("KSI-SVC-SIN has no controls - test fixture assumption broken")
	}

	var nodes []ir.Node
	for _, c := range controlIDs {
		id := ir.NodeID("synthetic:node-" + c.OSCAL())
		nodes = append(nodes, testNode(id, ir.ControlFamily(c.Family), c.Base, c.Enhancement))
	}
	g := ir.Graph{Nodes: nodes}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var sinResult *IndicatorResult
	for i := range results {
		if results[i].Indicator == "KSI-SVC-SIN" {
			sinResult = &results[i]
			break
		}
	}
	if sinResult == nil {
		t.Fatal("KSI-SVC-SIN missing from results")
	}
	if sinResult.Status != StatusSatisfied {
		t.Fatalf("KSI-SVC-SIN: status = %q, want %q; reason: %s", sinResult.Status, StatusSatisfied, sinResult.Reason)
	}
	if len(sinResult.Evidence) != len(nodes) {
		t.Errorf("KSI-SVC-SIN: len(Evidence) = %d, want %d (one per synthetic node)", len(sinResult.Evidence), len(nodes))
	}
}

// TestEvaluateEvidenceDedupedAcrossControls proves a single node whose
// Controls list names more than one control this indicator references
// contributes its ID to Evidence exactly once, not once per matching
// control (evidence_for used to be an array comprehension keyed on
// (node, control) pairs, duplicating any such node).
func TestEvaluateEvidenceDedupedAcrossControls(t *testing.T) {
	ds := loadVendoredDataset(t)
	sin, ok := ds.KSI["SVC"].Indicators["KSI-SVC-SIN"]
	if !ok {
		t.Fatal("KSI-SVC-SIN not found in vendored dataset - test fixture assumption broken")
	}
	controlIDs, err := sin.ControlIDs()
	if err != nil {
		t.Fatalf("KSI-SVC-SIN.ControlIDs(): %v", err)
	}

	// One node evidences the first two of SIN's controls at once (e.g. a
	// single resource that happens to satisfy both); the rest each get
	// their own single-control node, same as TestEvaluateSVCFullCoverageSatisfied.
	if len(controlIDs) < 2 {
		t.Fatal("KSI-SVC-SIN has fewer than 2 controls - test fixture assumption broken")
	}
	dual := ir.Node{
		ID:            "synthetic:dual-control-node",
		ControlFamily: ir.ControlFamily(controlIDs[0].Family),
		Controls: []ir.Control{
			{Family: ir.ControlFamily(controlIDs[0].Family), Base: controlIDs[0].Base, Enhancement: controlIDs[0].Enhancement},
			{Family: ir.ControlFamily(controlIDs[1].Family), Base: controlIDs[1].Base, Enhancement: controlIDs[1].Enhancement},
		},
		Kind:          "test_fact",
		Provenance:    testProvenance(),
		SchemaVersion: ir.SchemaVersion,
	}
	nodes := []ir.Node{dual}
	for _, c := range controlIDs[2:] {
		nodes = append(nodes, testNode(ir.NodeID("synthetic:node-"+c.OSCAL()), ir.ControlFamily(c.Family), c.Base, c.Enhancement))
	}
	g := ir.Graph{Nodes: nodes}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var sinResult *IndicatorResult
	for i := range results {
		if results[i].Indicator == "KSI-SVC-SIN" {
			sinResult = &results[i]
			break
		}
	}
	if sinResult == nil {
		t.Fatal("KSI-SVC-SIN missing from results")
	}
	if sinResult.Status != StatusSatisfied {
		t.Fatalf("KSI-SVC-SIN: status = %q, want %q; reason: %s", sinResult.Status, StatusSatisfied, sinResult.Reason)
	}
	if len(sinResult.Evidence) != len(nodes) {
		t.Errorf("KSI-SVC-SIN: len(Evidence) = %d, want %d (one per distinct node, not one per matched control) - got %v", len(sinResult.Evidence), len(nodes), sinResult.Evidence)
	}
	seen := map[string]bool{}
	for _, id := range sinResult.Evidence {
		if seen[id] {
			t.Errorf("KSI-SVC-SIN: Evidence contains duplicate id %q", id)
		}
		seen[id] = true
	}
}

// TestEvaluateEmptyGraphSVC confirms "no evidence collected for any
// control" is a distinct reason from the partial-coverage case, given a
// graph with no nodes at all.
func TestEvaluateEmptyGraphSVC(t *testing.T) {
	ds := loadVendoredDataset(t)
	results, err := Evaluate(context.Background(), ds, ir.Graph{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, r := range results {
		if r.Family != "SVC" {
			continue
		}
		if r.Status != StatusUndetermined {
			t.Errorf("%s: status = %q, want %q", r.Indicator, r.Status, StatusUndetermined)
		}
		if len(r.Evidence) != 0 {
			t.Errorf("%s: Evidence = %v, want none", r.Indicator, r.Evidence)
		}
	}
}

// TestEvaluateUnimplementedFamiliesAreUndetermined confirms every KSI
// family besides SVC - which has no Rego module yet - is represented in
// the result as an honest "not yet implemented" undetermined, one row per
// indicator the dataset defines, rather than silently missing (FR-6.7).
func TestEvaluateUnimplementedFamiliesAreUndetermined(t *testing.T) {
	ds := loadVendoredDataset(t)
	results, err := Evaluate(context.Background(), ds, ir.Graph{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	wantCount := map[string]int{}
	for family, theme := range ds.KSI {
		if family == "SVC" {
			continue
		}
		wantCount[family] = len(theme.Indicators)
	}

	gotCount := map[string]int{}
	for _, r := range results {
		if r.Family == "SVC" {
			continue
		}
		if r.Status != StatusUndetermined {
			t.Errorf("%s (%s): status = %q, want %q for an unimplemented family", r.Indicator, r.Family, r.Status, StatusUndetermined)
		}
		if r.RemediationHint == "" {
			t.Errorf("%s (%s): remediation_hint is empty", r.Indicator, r.Family)
		}
		gotCount[r.Family]++
	}

	for family, want := range wantCount {
		if gotCount[family] != want {
			t.Errorf("family %s: got %d results, want %d (one per indicator)", family, gotCount[family], want)
		}
	}
}

// TestEvaluateSortedByIndicator confirms Evaluate's output order is
// deterministic (sorted by indicator ID) regardless of ds.KSI's map
// iteration order.
func TestEvaluateSortedByIndicator(t *testing.T) {
	ds := loadVendoredDataset(t)
	results, err := Evaluate(context.Background(), ds, ir.Graph{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !sort.SliceIsSorted(results, func(i, j int) bool { return results[i].Indicator < results[j].Indicator }) {
		t.Error("results are not sorted by Indicator")
	}
}
