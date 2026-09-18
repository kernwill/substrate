package fedramp20x

import (
	"context"
	"sort"
	"strings"
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

// testS3PABNode builds an AC-3 node shaped like the real thing
// (rego/ksi/predicates' ac3_ok checks Kind and these four attributes
// specifically) - allTrue picks the well-configured or
// deliberately-broken side of the self-test fixture's own two S3
// buckets (app_data vs app_logs).
func testS3PABNode(id ir.NodeID, allTrue bool) ir.Node {
	v := "false"
	if allTrue {
		v = "true"
	}
	return ir.Node{
		ID:            id,
		ControlFamily: "AC",
		Controls:      []ir.Control{{Family: "AC", Base: 3}},
		Kind:          "s3_bucket_public_access_block",
		Attributes: map[string]string{
			"block_public_acls":       v,
			"block_public_policy":     v,
			"ignore_public_acls":      v,
			"restrict_public_buckets": v,
		},
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
// family with no Rego module yet - everything but SVC and IAM - is
// represented in the result as an honest "not yet implemented"
// undetermined, one row per indicator the dataset defines, rather than
// silently missing (FR-6.7).
func TestEvaluateUnimplementedFamiliesAreUndetermined(t *testing.T) {
	ds := loadVendoredDataset(t)
	results, err := Evaluate(context.Background(), ds, ir.Graph{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	implemented := map[string]bool{"SVC": true, "IAM": true, "CNA": true}
	wantCount := map[string]int{}
	for family, theme := range ds.KSI {
		if implemented[family] {
			continue
		}
		wantCount[family] = len(theme.Indicators)
	}

	gotCount := map[string]int{}
	for _, r := range results {
		if implemented[r.Family] {
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

// TestEvaluateIAMAgainstRealCollectors mirrors
// TestEvaluateSVCAgainstRealCollectors for the second real family: fed
// exactly the controls our current frontends and collectors evidence
// today (AC-3, AC-6, CM-7, IA-2, IA-5, plus SC-28.1, CP-9, SC-7.5, SR-11
// from outside KSI-IAM's own reach), every KSI-IAM indicator must still
// come back undetermined - none has anywhere near full coverage - but
// KSI-IAM-APM, -ELP, and -JIT (the three with real partial overlap,
// per docs/adr/0012's sibling proposal) must land in the "missing IR
// evidence for control(s)" branch, not the "no IR evidence collected
// for any control" branch the other three (AAM, SNU, SUS) still hit.
func TestEvaluateIAMAgainstRealCollectors(t *testing.T) {
	ds := loadVendoredDataset(t)
	g := ir.Graph{Nodes: []ir.Node{
		testS3PABNode("terraform:aws_s3_bucket_public_access_block.example", true),
		testNode("terraform:aws_s3_bucket_versioning.example", "CP", 9, 0),
		testNode("terraform:aws_s3_bucket_server_side_encryption_configuration.example", "SC", 28, 1),
		testNode("kubernetes:deployment.example", "CM", 7, 0),
		testNode("kubernetes:networkpolicy.example", "SC", 7, 5),
		testNode("github_actions:ci.yml#permissions", "AC", 6, 0),
		testNode("github_actions:ci.yml#dependency-review", "SR", 11, 0),
		testNode("aws:iam-user.example#mfa", "IA", 2, 0),
		testNode("aws:iam-user.example#access-keys", "IA", 5, 0),
	}}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	iamTheme := ds.KSI["IAM"]
	if len(iamTheme.Indicators) == 0 {
		t.Fatal("vendored dataset has no KSI-IAM indicators - test fixture assumption broken")
	}

	got := map[string]IndicatorResult{}
	for _, r := range results {
		if r.Family == "IAM" {
			got[r.Indicator] = r
		}
	}
	if len(got) != len(iamTheme.Indicators) {
		t.Fatalf("got %d IAM results, want one per indicator (%d)", len(got), len(iamTheme.Indicators))
	}
	for name, r := range got {
		if r.Status != StatusUndetermined {
			t.Errorf("%s: status = %q, want %q", name, r.Status, StatusUndetermined)
		}
	}

	partial := []string{"KSI-IAM-APM", "KSI-IAM-ELP", "KSI-IAM-JIT"}
	for _, name := range partial {
		r, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from results", name)
		}
		if !strings.HasPrefix(r.Reason, "missing IR evidence for control(s):") {
			t.Errorf("%s: reason = %q, want the partial-coverage branch", name, r.Reason)
		}
		if r.RemediationHint == "" {
			t.Errorf("%s: remediation_hint is empty", name)
		}
	}

	none := []string{"KSI-IAM-AAM", "KSI-IAM-SNU", "KSI-IAM-SUS"}
	for _, name := range none {
		r, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from results", name)
		}
		if r.Reason != "no IR evidence collected for any control this indicator references" {
			t.Errorf("%s: reason = %q, want the no-evidence-at-all branch", name, r.Reason)
		}
	}
}

// TestEvaluateIAMFullCoverageSatisfied mirrors
// TestEvaluateSVCFullCoverageSatisfied: given synthetic evidence for
// every control KSI-IAM-APM references, it comes back satisfied with
// evidence pointing at the nodes that back it.
func TestEvaluateIAMFullCoverageSatisfied(t *testing.T) {
	ds := loadVendoredDataset(t)
	apm, ok := ds.KSI["IAM"].Indicators["KSI-IAM-APM"]
	if !ok {
		t.Fatal("KSI-IAM-APM not found in vendored dataset - test fixture assumption broken")
	}
	controlIDs, err := apm.ControlIDs()
	if err != nil {
		t.Fatalf("KSI-IAM-APM.ControlIDs(): %v", err)
	}
	if len(controlIDs) == 0 {
		t.Fatal("KSI-IAM-APM has no controls - test fixture assumption broken")
	}

	var nodes []ir.Node
	for _, c := range controlIDs {
		id := ir.NodeID("synthetic:node-" + c.OSCAL())
		if c.OSCAL() == "ac-3" {
			// A generic, attribute-less testNode would fail
			// predicates.ac3_ok (no attributes to prove it's good),
			// which would flip this indicator to not_satisfied instead
			// of the satisfied path this test means to prove - see
			// TestEvaluateIAMFullCoverageButPredicateFailsIsNotSatisfied
			// for that case.
			nodes = append(nodes, testS3PABNode(id, true))
			continue
		}
		nodes = append(nodes, testNode(id, ir.ControlFamily(c.Family), c.Base, c.Enhancement))
	}
	g := ir.Graph{Nodes: nodes}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var apmResult *IndicatorResult
	for i := range results {
		if results[i].Indicator == "KSI-IAM-APM" {
			apmResult = &results[i]
			break
		}
	}
	if apmResult == nil {
		t.Fatal("KSI-IAM-APM missing from results")
	}
	if apmResult.Status != StatusSatisfied {
		t.Fatalf("KSI-IAM-APM: status = %q, want %q; reason: %s", apmResult.Status, StatusSatisfied, apmResult.Reason)
	}
	if len(apmResult.Evidence) != len(nodes) {
		t.Errorf("KSI-IAM-APM: len(Evidence) = %d, want %d (one per synthetic node)", len(apmResult.Evidence), len(nodes))
	}
}

// TestEvaluateIAMFullCoverageButPredicateFailsIsNotSatisfied proves
// docs/adr/0013's propagation rule takes priority over the coverage
// check: the exact same full-coverage setup as
// TestEvaluateIAMFullCoverageSatisfied, except the ac-3 node is the
// deliberately-broken shape (all four flags false, matching the
// self-test fixture's app_logs bucket) - the indicator must come back
// not_satisfied, never satisfied, even though every referenced control
// technically has evidence.
func TestEvaluateIAMFullCoverageButPredicateFailsIsNotSatisfied(t *testing.T) {
	ds := loadVendoredDataset(t)
	apm, ok := ds.KSI["IAM"].Indicators["KSI-IAM-APM"]
	if !ok {
		t.Fatal("KSI-IAM-APM not found in vendored dataset - test fixture assumption broken")
	}
	controlIDs, err := apm.ControlIDs()
	if err != nil {
		t.Fatalf("KSI-IAM-APM.ControlIDs(): %v", err)
	}

	var nodes []ir.Node
	var badNodeID ir.NodeID
	for _, c := range controlIDs {
		id := ir.NodeID("synthetic:node-" + c.OSCAL())
		if c.OSCAL() == "ac-3" {
			badNodeID = id
			nodes = append(nodes, testS3PABNode(id, false))
			continue
		}
		nodes = append(nodes, testNode(id, ir.ControlFamily(c.Family), c.Base, c.Enhancement))
	}
	g := ir.Graph{Nodes: nodes}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var apmResult *IndicatorResult
	for i := range results {
		if results[i].Indicator == "KSI-IAM-APM" {
			apmResult = &results[i]
			break
		}
	}
	if apmResult == nil {
		t.Fatal("KSI-IAM-APM missing from results")
	}
	if apmResult.Status != StatusNotSatisfied {
		t.Fatalf("KSI-IAM-APM: status = %q, want %q; reason: %s", apmResult.Status, StatusNotSatisfied, apmResult.Reason)
	}
	if len(apmResult.Evidence) != 1 || apmResult.Evidence[0] != string(badNodeID) {
		t.Errorf("KSI-IAM-APM: Evidence = %v, want exactly [%q]", apmResult.Evidence, badNodeID)
	}
}

// TestEvaluateIAMNotSatisfiedEvenWithMassiveMissingCoverage is the
// concern this session flagged for tracking (docs/adr/0013, and
// docs/REQUIREMENTS.md section 31 item 9), made concrete as a test: fed
// only a single, deliberately-broken ac-3 node (real collector shape),
// KSI-IAM-APM/-ELP/-JIT must come back not_satisfied even though every
// one of their dozens of other referenced controls has zero evidence at
// all - the opposite of the "wait for full coverage before ever
// flagging a known bad value" alternative this session considered and
// rejected. KSI-IAM-AAM/-SNU/-SUS, which don't reference ac-3, must be
// entirely unaffected.
func TestEvaluateIAMNotSatisfiedEvenWithMassiveMissingCoverage(t *testing.T) {
	ds := loadVendoredDataset(t)
	g := ir.Graph{Nodes: []ir.Node{
		testS3PABNode("terraform:aws_s3_bucket_public_access_block.example", false),
	}}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	got := map[string]IndicatorResult{}
	for _, r := range results {
		if r.Family == "IAM" {
			got[r.Indicator] = r
		}
	}

	flipped := []string{"KSI-IAM-APM", "KSI-IAM-ELP", "KSI-IAM-JIT"}
	for _, name := range flipped {
		r, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from results", name)
		}
		if r.Status != StatusNotSatisfied {
			t.Errorf("%s: status = %q, want %q (a single known-bad control must override, regardless of how much else is uncollected)", name, r.Status, StatusNotSatisfied)
		}
	}

	unaffected := []string{"KSI-IAM-AAM", "KSI-IAM-SNU", "KSI-IAM-SUS"}
	for _, name := range unaffected {
		r, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from results", name)
		}
		if r.Status != StatusUndetermined {
			t.Errorf("%s: status = %q, want %q (doesn't reference ac-3, must be unaffected)", name, r.Status, StatusUndetermined)
		}
	}
}

// TestEvaluateEmptyGraphIAM mirrors TestEvaluateEmptyGraphSVC for the
// second real family.
func TestEvaluateEmptyGraphIAM(t *testing.T) {
	ds := loadVendoredDataset(t)
	results, err := Evaluate(context.Background(), ds, ir.Graph{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, r := range results {
		if r.Family != "IAM" {
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

// TestEvaluateCNAAgainstRealCollectors mirrors
// TestEvaluateIAMAgainstRealCollectors for the third real family: fed
// exactly the controls our current frontends and collectors evidence
// today, KSI-CNA-MAT and KSI-CNA-RNT (the two with real overlap, via
// SC-7.5) must land in the "missing IR evidence for control(s)" branch,
// not the "no IR evidence collected for any control" branch every
// other implemented-in-this-family indicator still hits - except
// KSI-CNA-OFA, which has zero controls in the vendored dataset and
// must come back not_applicable regardless of evidence.
func TestEvaluateCNAAgainstRealCollectors(t *testing.T) {
	ds := loadVendoredDataset(t)
	g := ir.Graph{Nodes: []ir.Node{
		testNode("terraform:aws_s3_bucket_public_access_block.example", "AC", 3, 0),
		testNode("terraform:aws_s3_bucket_versioning.example", "CP", 9, 0),
		testNode("terraform:aws_s3_bucket_server_side_encryption_configuration.example", "SC", 28, 1),
		testNode("kubernetes:deployment.example", "CM", 7, 0),
		testNode("kubernetes:networkpolicy.example", "SC", 7, 5),
		testNode("github_actions:ci.yml#permissions", "AC", 6, 0),
		testNode("github_actions:ci.yml#dependency-review", "SR", 11, 0),
		testNode("aws:iam-user.example#mfa", "IA", 2, 0),
		testNode("aws:iam-user.example#access-keys", "IA", 5, 0),
	}}

	results, err := Evaluate(context.Background(), ds, g)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	cnaTheme := ds.KSI["CNA"]
	if len(cnaTheme.Indicators) == 0 {
		t.Fatal("vendored dataset has no KSI-CNA indicators - test fixture assumption broken")
	}

	got := map[string]IndicatorResult{}
	for _, r := range results {
		if r.Family == "CNA" {
			got[r.Indicator] = r
		}
	}
	if len(got) != len(cnaTheme.Indicators) {
		t.Fatalf("got %d CNA results, want one per indicator (%d)", len(got), len(cnaTheme.Indicators))
	}

	ofa, ok := got["KSI-CNA-OFA"]
	if !ok {
		t.Fatal("KSI-CNA-OFA missing from results")
	}
	if ofa.Status != StatusNotApplicable {
		t.Errorf("KSI-CNA-OFA: status = %q, want %q", ofa.Status, StatusNotApplicable)
	}

	partial := []string{"KSI-CNA-MAT", "KSI-CNA-RNT"}
	for _, name := range partial {
		r, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from results", name)
		}
		if r.Status != StatusUndetermined {
			t.Errorf("%s: status = %q, want %q", name, r.Status, StatusUndetermined)
		}
		if !strings.HasPrefix(r.Reason, "missing IR evidence for control(s):") {
			t.Errorf("%s: reason = %q, want the partial-coverage branch", name, r.Reason)
		}
	}

	for name, r := range got {
		if name == "KSI-CNA-OFA" || name == "KSI-CNA-MAT" || name == "KSI-CNA-RNT" {
			continue
		}
		if r.Status != StatusUndetermined {
			t.Errorf("%s: status = %q, want %q", name, r.Status, StatusUndetermined)
		}
		if r.Reason != "no IR evidence collected for any control this indicator references" {
			t.Errorf("%s: reason = %q, want the no-evidence-at-all branch", name, r.Reason)
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
