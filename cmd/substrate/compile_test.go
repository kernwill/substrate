package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kernwill/substrate/internal/goldentest"
)

// TestGoldenCompile is T-008's own "done when" case: it runs
// testdata/fixtures/minimal (and any other fixture directory added
// alongside it later) through the real substrate compile command and
// diffs the result against testdata/fixtures/<name>/expected/ via the
// goldentest harness.
//
// substrate compile isn't implemented yet (Phase 1), so today's
// expected/ records that stub's exit code and stderr message, not real
// compiled output - see testdata/fixtures/minimal/NOTES.md. That's
// enough to prove the harness itself is wired correctly end to end
// ahead of the parser, which is what T-008 asks for.
//
// Regenerate with:
//
//	SUBSTRATE_UPDATE_GOLDEN=1 go test ./cmd/substrate -run TestGoldenCompile
//
// then review the diff before committing.
func TestGoldenCompile(t *testing.T) {
	goldentest.Run(t, "../../testdata/fixtures", goldenUpdateRequested(), runCompileFixture)
}

// runCompileFixture passes the whole fixture directory - including its
// own expected/ and NOTES.md - as --source. That's fine while compile
// is a stub that reads nothing, but it's a known, deliberate limitation
// once real front-end parsing lands (see testdata/fixtures/minimal/
// NOTES.md): the real front end will need its own include/exclude rules
// for what counts as compiler input (a .gitignore-style filter, most
// likely), which is Phase 1 design work, not something to anticipate here.

// runCompileFixture is the goldentest.Runner for the compile pipeline:
// it invokes runCompile in-process (no subprocess, no prebuilt binary
// required - consistent with how the rules show/diff golden tests
// already work) against fixtureDir, and turns the result into named
// artifacts: every file substrate compile wrote under --out (empty
// today, since the pipeline doesn't exist yet), plus the exit code and
// captured stdout/stderr.
func runCompileFixture(t *testing.T, fixtureDir string) map[string][]byte {
	t.Helper()
	outDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", fixtureDir, "--out", outDir}, &stdout, &stderr)

	artifacts := map[string][]byte{
		"stdout.txt":    stdout.Bytes(),
		"stderr.txt":    stderr.Bytes(),
		"exit_code.txt": []byte(strconv.Itoa(code)),
	}

	err := filepath.WalkDir(outDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outDir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		artifacts["out/"+filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatalf("walk --out dir %s: %v", outDir, err)
	}
	return artifacts
}

// TestCompileLeavesNoTempDirectoryOnSuccess guards the atomic-write fix:
// runCompile writes to a "<out>.tmp" sibling and renames it into place at
// the very end (see runCompile's own doc comment), and that sibling must
// never survive a successful run.
func TestCompileLeavesNoTempDirectoryOnSuccess(t *testing.T) {
	outDir := t.TempDir()
	out := filepath.Join(outDir, "out")

	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCompile exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("out+\".tmp\" = %v, want it gone after a successful run", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("out: %v, want it to exist after a successful run", err)
	}
}

// TestCompileReportsMissingConventionDirectories confirms the compile
// summary distinguishes "this source has no Kubernetes manifests or
// GitHub Actions workflows at all" from "we looked in k8s/ and
// .github/workflows/ and neither exists" - collapsing both into the same
// "0 resource(s)" line was the gap resourceCount fixes.
func TestCompileReportsMissingConventionDirectories(t *testing.T) {
	source := t.TempDir() // no k8s/, no .github/workflows/, no *.tf either
	out := filepath.Join(t.TempDir(), "out")

	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", source, "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCompile exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "k8s not found") {
		t.Errorf("stdout = %q, want it to name the missing k8s directory", got)
	}
	if !strings.Contains(got, "workflows not found") {
		t.Errorf("stdout = %q, want it to name the missing .github/workflows directory", got)
	}
}
