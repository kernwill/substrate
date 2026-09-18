package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

func testNode(id ir.NodeID, family ir.ControlFamily, base, enhancement int) ir.Node {
	return ir.Node{
		ID:            id,
		ControlFamily: family,
		Controls:      []ir.Control{{Family: family, Base: base, Enhancement: enhancement}},
		Kind:          "test_fact",
		Provenance: provenance.Record{
			SourceType:       "test",
			Locator:          provenance.Locator{Path: "test.tf", Line: 1},
			Timestamp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			CollectorVersion: "test/v0",
			Basis:            provenance.Declared,
			Confidence:       provenance.Deterministic,
		},
		SchemaVersion: ir.SchemaVersion,
	}
}

func writeNodesFile(t *testing.T, dir string, nodes []ir.Node) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, "nodes.jsonl"))
	if err != nil {
		t.Fatalf("create nodes.jsonl: %v", err)
	}
	defer f.Close()
	if err := ir.WriteNodesJSONL(f, nodes); err != nil {
		t.Fatalf("write nodes.jsonl: %v", err)
	}
}

func TestParseControlQueryAcceptsAllThreeNotations(t *testing.T) {
	cases := []struct {
		input          string
		wantFamily     ir.ControlFamily
		wantBase       int
		wantEnhance    int
		wantHasEnhance bool
	}{
		{"AC-2", "AC", 2, 0, false},
		{"ac-2", "AC", 2, 0, false},
		{"AC-2.1", "AC", 2, 1, true},
		{"AC-2(1)", "AC", 2, 1, true},
		{"sc-28.1", "SC", 28, 1, true},
	}
	for _, c := range cases {
		q, err := parseControlQuery(c.input)
		if err != nil {
			t.Errorf("parseControlQuery(%q): %v", c.input, err)
			continue
		}
		if q.Family != c.wantFamily || q.Base != c.wantBase || q.Enhancement != c.wantEnhance || q.HasEnhancement != c.wantHasEnhance {
			t.Errorf("parseControlQuery(%q) = %+v, want family=%s base=%d enhancement=%d hasEnhancement=%v",
				c.input, q, c.wantFamily, c.wantBase, c.wantEnhance, c.wantHasEnhance)
		}
	}
}

func TestParseControlQueryRejectsGarbage(t *testing.T) {
	for _, input := range []string{"", "not-a-control", "AC", "123", "AC-"} {
		if _, err := parseControlQuery(input); err == nil {
			t.Errorf("parseControlQuery(%q): got nil error, want a real error", input)
		}
	}
}

// TestControlQueryMatchesEnhancementsOfBaseControl confirms querying a
// bare base control (e.g. "SC-28") matches a node whose own control is
// an enhancement of it (SC-28(1)) - an enhancement's evidence still
// bears on the control being asked about.
func TestControlQueryMatchesEnhancementsOfBaseControl(t *testing.T) {
	q, err := parseControlQuery("SC-28")
	if err != nil {
		t.Fatalf("parseControlQuery: %v", err)
	}
	if !q.matchesControl([]ir.Control{{Family: "SC", Base: 28, Enhancement: 1}}) {
		t.Error("SC-28 query did not match SC-28(1) - an enhancement's evidence should bear on its base control")
	}
}

// TestControlQueryWithEnhancementDoesNotMatchOtherEnhancements confirms
// the reverse: querying a SPECIFIC enhancement does not match a
// different enhancement of the same base control.
func TestControlQueryWithEnhancementDoesNotMatchOtherEnhancements(t *testing.T) {
	q, err := parseControlQuery("AC-2.1")
	if err != nil {
		t.Fatalf("parseControlQuery: %v", err)
	}
	if q.matchesControl([]ir.Control{{Family: "AC", Base: 2, Enhancement: 2}}) {
		t.Error("AC-2.1 query matched AC-2(2) - querying a specific enhancement must not match a different one")
	}
}

func TestControlQueryMatchesFamilyOnlyFact(t *testing.T) {
	q, err := parseControlQuery("AC-3")
	if err != nil {
		t.Fatalf("parseControlQuery: %v", err)
	}
	if !q.matchesFamilyOnly("AC") {
		t.Error("AC-3 query did not match a fact carrying only the AC family")
	}
	if q.matchesFamilyOnly("SC") {
		t.Error("AC-3 query matched an SC-family-only fact")
	}
}

func TestRunIRQueryFindsMatchingNode(t *testing.T) {
	dir := t.TempDir()
	writeNodesFile(t, dir, []ir.Node{
		testNode("node-ac3", "AC", 3, 0),
		testNode("node-sc28", "SC", 28, 1),
	})

	var stdout, stderr strings.Builder
	code := runIRQuery([]string{"--dir", dir, "--control", "AC-3"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "node-ac3") {
		t.Errorf("stdout = %q, want it to contain node-ac3", stdout.String())
	}
	if strings.Contains(stdout.String(), "node-sc28") {
		t.Errorf("stdout = %q, want it to NOT contain the unrelated node-sc28", stdout.String())
	}
}

func TestRunIRQueryReportsNoMatches(t *testing.T) {
	dir := t.TempDir()
	writeNodesFile(t, dir, []ir.Node{testNode("node-ac3", "AC", 3, 0)})

	var stdout, stderr strings.Builder
	code := runIRQuery([]string{"--dir", dir, "--control", "AU-11"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (zero matches is a valid result, not an error); stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no facts") {
		t.Errorf("stdout = %q, want a clear \"no facts found\" message", stdout.String())
	}
}

func TestRunIRQueryIncludesProvenance(t *testing.T) {
	dir := t.TempDir()
	writeNodesFile(t, dir, []ir.Node{testNode("node-ac3", "AC", 3, 0)})

	var stdout, stderr strings.Builder
	code := runIRQuery([]string{"--dir", dir, "--control", "AC-3"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	for _, want := range []string{"test.tf:1", "declared", "deterministic", "test/v0"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout missing %q (FR-5.5's \"with provenance\" is the point, not optional detail): %s", want, stdout.String())
		}
	}
}

func TestRunIRQueryJSONFormat(t *testing.T) {
	dir := t.TempDir()
	writeNodesFile(t, dir, []ir.Node{testNode("node-ac3", "AC", 3, 0)})

	var stdout, stderr strings.Builder
	code := runIRQuery([]string{"--dir", dir, "--control", "AC-3", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"id": "node-ac3"`) {
		t.Errorf("stdout = %q, want valid JSON containing node-ac3", stdout.String())
	}
}

func TestRunIRQueryRejectsBadControlSyntax(t *testing.T) {
	dir := t.TempDir()
	writeNodesFile(t, dir, nil)

	var stdout, stderr strings.Builder
	code := runIRQuery([]string{"--dir", dir, "--control", "not-a-control"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRunIRQueryRequiresBothFlags(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runIRQuery(nil, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRunIRQueryMissingNodesFileFailsLoudly(t *testing.T) {
	dir := t.TempDir() // no nodes.jsonl written
	var stdout, stderr strings.Builder
	code := runIRQuery([]string{"--dir", dir, "--control", "AC-3"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (a missing nodes.jsonl is a real error, not zero results)", code)
	}
}
