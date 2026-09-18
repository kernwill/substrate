package githubactions

import (
	"testing"

	"github.com/kernwill/substrate/internal/redact"
)

// TestParseRedactsSecretShapedValue is FR-4.5's own "testable"
// requirement: GitHub Actions encourages ${{ secrets.X }} references
// instead of literal values, but nothing stops a workflow author from
// hardcoding one anyway, and Parse's own raw output is written straight
// to disk (cmd/substrate's github_actions.json) with no further
// scrubbing step downstream.
func TestParseRedactsSecretShapedValue(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
env:
  DEPLOY_TOKEN: abc123supersecret
  REGION: us-east-1
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
	env, ok := g.Workflows[0].Attributes["env"].(map[string]any)
	if !ok {
		t.Fatalf("env = %+v, not a map", g.Workflows[0].Attributes["env"])
	}
	if got := env["DEPLOY_TOKEN"]; got != redact.Placeholder {
		t.Errorf("env.DEPLOY_TOKEN = %v, want %q", got, redact.Placeholder)
	}
	if got, want := env["REGION"], "us-east-1"; got != want {
		t.Errorf("env.REGION = %v, want %q (unrelated value must survive untouched)", got, want)
	}
}

// TestParseDoesNotRedactPermissionsBlock is a regression test:
// redact.Value's generic key-name pass matches "token" as a substring
// of "id-token" - the standard OIDC permission scope name - which
// silently replaced a real scope level ("write") with
// redact.Placeholder before mapPermissions (ir.go) ever read it,
// corrupting the already-reviewed AC-6 evidence mapping. Every
// permissions value is one of a fixed, closed enum ("read"/"write"/
// "none"), never secret material, so the whole "permissions" block must
// survive Parse completely unredacted.
func TestParseDoesNotRedactPermissionsBlock(t *testing.T) {
	dir := t.TempDir()
	writeWorkflow(t, dir, "ci.yml", `
name: CI
on: push
permissions:
  contents: read
  id-token: write
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
	perms, ok := g.Workflows[0].Attributes["permissions"].(map[string]any)
	if !ok {
		t.Fatalf("permissions = %+v, not a map", g.Workflows[0].Attributes["permissions"])
	}
	if got, want := perms["id-token"], "write"; got != want {
		t.Errorf("permissions.id-token = %v, want %q (never redacted - it's a scope level, not a secret)", got, want)
	}
	if got, want := perms["contents"], "read"; got != want {
		t.Errorf("permissions.contents = %v, want %q", got, want)
	}
}
