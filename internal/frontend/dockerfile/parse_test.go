package dockerfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kernwill/substrate/internal/provenance"
)

func writeDockerfile(t *testing.T, dir, name, content string) {
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

// TestParseVendoredMinimalFixture is FR-2.7's own done criterion for
// what this package extracts from a real Dockerfile: the three-stage
// build at testdata/fixtures/minimal/Dockerfile covers a digest-pinned
// external image, a reference to an earlier stage, and a tag-only
// (unpinned) external image.
func TestParseVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 3 {
		t.Fatalf("got %d stages, want 3", len(g.Stages))
	}

	builder := g.Stages[0]
	if builder.Address.Name != "builder" {
		t.Errorf("stage 0 Address.Name = %q, want builder", builder.Address.Name)
	}
	if builder.Image.Kind != BaseImageExternal || builder.Image.Repository != "golang" || builder.Image.Tag != "1.22" || builder.Image.Digest == "" {
		t.Errorf("builder.Image = %+v, want external golang:1.22 pinned to a digest", builder.Image)
	}

	test := g.Stages[1]
	if test.Address.Name != "test" {
		t.Errorf("stage 1 Address.Name = %q, want test", test.Address.Name)
	}
	if test.Image.Kind != BaseImageLocalStage {
		t.Errorf("test.Image.Kind = %q, want local_stage (FROM builder)", test.Image.Kind)
	}

	final := g.Stages[2]
	if final.Address.Name != "" {
		t.Errorf("stage 2 Address.Name = %q, want empty (unnamed final stage)", final.Address.Name)
	}
	if final.Image.Kind != BaseImageExternal || final.Image.Repository != "gcr.io/distroless/static-debian12" || final.Image.Tag != "latest" || final.Image.Digest != "" {
		t.Errorf("final.Image = %+v, want external gcr.io/distroless/static-debian12:latest with no digest", final.Image)
	}

	for _, s := range g.Stages {
		if err := s.Provenance.Validate(); err != nil {
			t.Errorf("stage %s: invalid Provenance: %v", s.Address, err)
		}
		if s.Provenance.Confidence != provenance.Deterministic {
			t.Errorf("stage %s: Provenance.Confidence = %q, want deterministic", s.Address, s.Provenance.Confidence)
		}
	}
}

func TestParseFromScratch(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM scratch\nCOPY app /app\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(g.Stages))
	}
	if g.Stages[0].Image.Kind != BaseImageScratch {
		t.Errorf("Image.Kind = %q, want scratch", g.Stages[0].Image.Kind)
	}
	if g.Stages[0].Provenance.Confidence != provenance.Deterministic {
		t.Errorf("Provenance.Confidence = %q, want deterministic (scratch is a real, resolved fact)", g.Stages[0].Provenance.Confidence)
	}
}

func TestParseUnresolvedBuildArg(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM ${BASE_IMAGE}\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(g.Stages))
	}
	s := g.Stages[0]
	if s.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("Provenance.Confidence = %q, want unresolved", s.Provenance.Confidence)
	}
	if s.Provenance.UnresolvedReason == "" {
		t.Error("Provenance.UnresolvedReason is empty")
	}
	if s.Image != (BaseImage{}) {
		t.Errorf("Image = %+v, want zero value on an unresolved stage", s.Image)
	}
}

func TestParseRegistryPortNotMistakenForTag(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM localhost:5000/myimage:v2\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	img := g.Stages[0].Image
	if img.Repository != "localhost:5000/myimage" || img.Tag != "v2" {
		t.Errorf("Image = %+v, want repository \"localhost:5000/myimage\" tag \"v2\" (the port must not be mistaken for a tag separator)", img)
	}
}

func TestParseNoTagOrDigest(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM alpine\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	img := g.Stages[0].Image
	if img.Kind != BaseImageExternal || img.Repository != "alpine" || img.Tag != "" || img.Digest != "" {
		t.Errorf("Image = %+v, want external alpine with no tag or digest recorded (not fabricated 'latest')", img)
	}
}

func TestParseLineContinuation(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM \\\n    alpine:3.19\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(g.Stages))
	}
	img := g.Stages[0].Image
	if img.Repository != "alpine" || img.Tag != "3.19" {
		t.Errorf("Image = %+v, want repository alpine tag 3.19 (continuation line joined)", img)
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "# syntax=docker/dockerfile:1\n\n# a comment\nFROM alpine:3.19\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(g.Stages))
	}
	if g.Stages[0].Provenance.Locator.Line != 4 {
		t.Errorf("Locator.Line = %d, want 4 (the actual FROM line, not shifted by the leading comments)", g.Stages[0].Provenance.Locator.Line)
	}
}

func TestParseRejectsFromWithNoArgument(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM\n")
	initGitRepo(t, dir)

	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on a FROM instruction with no image argument, want error")
	}
}

func TestParseIgnoresNonDockerfiles(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile", "FROM alpine:3.19\n")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a dockerfile"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(g.Stages))
	}
}

func TestParseMatchesDockerfileSuffixVariant(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, "Dockerfile.prod", "FROM alpine:3.19\n")
	initGitRepo(t, dir)

	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Stages) != 1 {
		t.Fatalf("got %d stages, want 1", len(g.Stages))
	}
}
