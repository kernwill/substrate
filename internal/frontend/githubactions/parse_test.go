package githubactions

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeWorkflow(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=substrate-test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=substrate-test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "test fixture")
}

func workflowByPath(t *testing.T, g *WorkflowGraph, path string) Workflow {
	t.Helper()
	for _, w := range g.Workflows {
		if w.Address.Path == path {
			return w
		}
	}
	t.Fatalf("no workflow %q in graph (have %d workflows)", path, len(g.Workflows))
	return Workflow{}
}

// TestParseVendoredMinimalFixture is FR-2.6's own done criterion for
// what's actually static-file-parseable: parse the real vendored
// ci.yml and check its name, permissions block, and jobs are captured
// faithfully.
func TestParseVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal/.github/workflows")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Workflows) != 1 {
		t.Fatalf("got %d workflows, want 1", len(g.Workflows))
	}
	w := workflowByPath(t, g, filepath.Join("../../../testdata/fixtures/minimal/.github/workflows", "ci.yml"))
	if w.Address.Name != "CI" {
		t.Errorf("Address.Name = %q, want CI", w.Address.Name)
	}
	perms, ok := w.Attributes["permissions"].(map[string]any)
	if !ok {
		t.Fatalf("permissions has type %T, want map[string]any", w.Attributes["permissions"])
	}
	if got, want := perms["contents"], "read"; got != want {
		t.Errorf("permissions.contents = %v, want %v", got, want)
	}
	jobs, ok := w.Attributes["jobs"].(map[string]any)
	if !ok || len(jobs) != 2 {
		t.Fatalf("jobs = %v, want a 2-entry map", w.Attributes["jobs"])
	}
	if err := w.Provenance.Validate(); err != nil {
		t.Errorf("invalid Provenance: %v", err)
	}
}

func TestParseWorkflowWithoutNameHasEmptyName(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
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
	if len(g.Workflows) != 1 {
		t.Fatalf("got %d workflows, want 1", len(g.Workflows))
	}
	if g.Workflows[0].Address.Name != "" {
		t.Errorf("Address.Name = %q, want empty", g.Workflows[0].Address.Name)
	}
}

func TestParseKeepsOnAsStringKey(t *testing.T) {
	// "on" is a YAML 1.1 boolean literal; decoding into map[string]any
	// must keep it as the literal string key "on", not resolve it to a
	// boolean - the classic GitHub Actions YAML gotcha.
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on:
  push:
    branches: [main]
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
	w := g.Workflows[0]
	if _, ok := w.Attributes["on"]; !ok {
		t.Errorf("Attributes = %v, want an \"on\" key", w.Attributes)
	}
}

func TestParseRejectsSyntaxError(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", "on: [unterminated")
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on malformed YAML, want error")
	}
}

func TestParseSkipsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "empty.yml", "")
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Workflows) != 0 {
		t.Errorf("got %d workflows, want 0", len(g.Workflows))
	}
}

func TestParseIsOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "z.yml", "name: z\non: push\njobs: {}\n")
	writeWorkflow(t, dir, "a.yml", "name: a\non: push\njobs: {}\n")
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Workflows) != 2 {
		t.Fatalf("got %d workflows, want 2", len(g.Workflows))
	}
	if g.Workflows[0].Address.Name != "a" || g.Workflows[1].Address.Name != "z" {
		t.Errorf("workflows not sorted by path: got %s, %s", g.Workflows[0].Address, g.Workflows[1].Address)
	}
}

func TestParseIgnoresNonWorkflowFiles(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", "name: CI\non: push\njobs: {}\n")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a workflow"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Workflows) != 1 {
		t.Fatalf("got %d workflows, want 1", len(g.Workflows))
	}
}
