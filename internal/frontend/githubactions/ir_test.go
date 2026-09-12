package githubactions

import (
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestToIRVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal/.github/workflows")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (permissions + dependency-review)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}
	addr := WorkflowAddress{Path: workflowPathFixture(t)}

	perms, ok := byID[nodeID(addr, "permissions")]
	if !ok {
		t.Fatal("no permissions node")
	}
	if perms.ControlFamily != "AC" || len(perms.Controls) != 1 || perms.Controls[0] != (ir.Control{Family: "AC", Base: 6}) {
		t.Errorf("permissions node control = %+v/%+v, want AC/AC-6", perms.ControlFamily, perms.Controls)
	}
	if got, want := perms.Attributes["contents"], "read"; got != want {
		t.Errorf("permissions.contents = %q, want %q", got, want)
	}

	depReview, ok := byID[nodeID(addr, "dependency-review[dependency-review]")]
	if !ok {
		t.Fatal("no dependency-review node")
	}
	if depReview.ControlFamily != "SR" || len(depReview.Controls) != 1 || depReview.Controls[0] != (ir.Control{Family: "SR", Base: 11}) {
		t.Errorf("dependency-review node control = %+v/%+v, want SR/SR-11", depReview.ControlFamily, depReview.Controls)
	}
}

func workflowPathFixture(t *testing.T) string {
	t.Helper()
	g, err := Parse("../../../testdata/fixtures/minimal/.github/workflows")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Workflows) != 1 {
		t.Fatalf("got %d workflows, want 1", len(g.Workflows))
	}
	return g.Workflows[0].Address.Path
}

func TestMapPermissionsSkipsWorkflowWithNoPermissionsBlock(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0 (no explicit permissions block, nothing to measure)", len(irGraph.Nodes))
	}
}

func TestMapPermissionsRecordsBroadScopeVerbatim(t *testing.T) {
	// FR-5.9: the mapping records whatever is declared, even a
	// permissive scope - it does not judge the value.
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(irGraph.Nodes))
	}
	if got, want := irGraph.Nodes[0].Attributes["contents"], "write"; got != want {
		t.Errorf("contents = %q, want %q (verbatim, not judged)", got, want)
	}
}

// TestMapPermissionsRecordsExplicitEmptyBlock is a regression test: an
// earlier version of mapPermissions treated "permissions: {}" the same
// as no permissions block at all (both fell through the same `len ==
// 0` check), discarding GitHub's own strictest-possible declaration -
// every scope explicitly set to no access - as if nothing had been
// declared.
func TestMapPermissionsRecordsExplicitEmptyBlock(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (an explicit empty block is a real, strictest-possible declaration, not an absent one)", len(irGraph.Nodes))
	}
	if got := irGraph.Nodes[0].Attributes; len(got) != 0 {
		t.Errorf("Attributes = %v, want empty (no scopes granted)", got)
	}
}

func TestMapDependencyReviewIgnoresUnrelatedActions(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0 (checkout is not dependency-review)", len(irGraph.Nodes))
	}
}

// TestMapDependencyReviewIsOrderIndependent is a regression test for a
// map-iteration-order bug caught before it ever reached a fixture:
// mapDependencyReview originally iterated the decoded "jobs" map
// directly, whose Go map iteration order is randomized per run. A
// workflow with two or more matching jobs would then produce this
// function's own node slice in a different order on different runs.
func TestMapDependencyReviewIsOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
jobs:
  z-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
  a-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var first []ir.NodeID
	for i := 0; i < 20; i++ {
		irGraph, err := ToIR(g)
		if err != nil {
			t.Fatalf("ToIR: %v", err)
		}
		if len(irGraph.Nodes) != 2 {
			t.Fatalf("run %d: got %d nodes, want 2", i, len(irGraph.Nodes))
		}
		ids := []ir.NodeID{irGraph.Nodes[0].ID, irGraph.Nodes[1].ID}
		if first == nil {
			first = ids
			continue
		}
		if ids[0] != first[0] || ids[1] != first[1] {
			t.Fatalf("run %d: node order = %v, want stable order %v across every run", i, ids, first)
		}
	}
	if first[0] >= first[1] {
		t.Errorf("node order = %v, want sorted by job name (a-job before z-job)", first)
	}
}

func TestUsesActionMatchesWithAndWithoutVersion(t *testing.T) {
	cases := []struct {
		uses string
		want bool
	}{
		{"actions/dependency-review-action@v4", true},
		{"actions/dependency-review-action@main", true},
		{"actions/dependency-review-action", true},
		{"actions/checkout@v4", false},
		{"someorg/actions/dependency-review-action@v4", false},
	}
	for _, c := range cases {
		if got := usesAction(c.uses, dependencyReviewAction); got != c.want {
			t.Errorf("usesAction(%q, %q) = %v, want %v", c.uses, dependencyReviewAction, got, c.want)
		}
	}
}
