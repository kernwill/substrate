package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
	"github.com/kernwill/substrate/internal/goldentest"
	"github.com/kernwill/substrate/internal/rules"
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

// TestCompileWritesKSIResults exercises FR-6's wiring into the compile
// pipeline directly, rather than relying solely on the golden fixture
// (which a careless SUBSTRATE_UPDATE_GOLDEN=1 regeneration could paper
// over without anyone noticing a real regression, per CLAUDE.md's own
// warning about that file). It cross-checks the written artifact against
// the vendored dataset's own indicator count instead of hardcoding a
// number that would silently drift the next time the dataset updates.
func TestCompileWritesKSIResults(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	if code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("runCompile exit code = %d, want 0; stderr: %s", code, stderr.String())
	}

	raw, err := os.ReadFile(filepath.Join(out, "ksi_results.json"))
	if err != nil {
		t.Fatalf("read ksi_results.json: %v", err)
	}
	var results []fedramp20x.IndicatorResult
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("parse ksi_results.json: %v", err)
	}

	ds, err := rules.Default()
	if err != nil {
		t.Fatalf("rules.Default(): %v", err)
	}
	wantIndicators := 0
	for _, theme := range ds.KSI {
		wantIndicators += len(theme.Indicators)
	}
	if len(results) != wantIndicators {
		t.Errorf("got %d KSI results, want %d (one per indicator in the vendored dataset)", len(results), wantIndicators)
	}

	for _, r := range results {
		switch r.Status {
		case fedramp20x.StatusSatisfied, fedramp20x.StatusNotSatisfied, fedramp20x.StatusUndetermined,
			fedramp20x.StatusNotApplicable, fedramp20x.StatusRequiresAttestation:
		default:
			t.Errorf("%s: status = %q, not a recognized FR-6.6 status", r.Indicator, r.Status)
		}
		if r.Reason == "" {
			t.Errorf("%s: reason is empty", r.Indicator)
		}
	}

	if !strings.Contains(stdout.String(), "evaluated") || !strings.Contains(stdout.String(), "KSI indicator") {
		t.Errorf("stdout = %q, want a KSI evaluation summary", stdout.String())
	}
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

// TestCompileRerunLeavesNoBackupDirectory exercises the swap path
// TestCompileLeavesNoTempDirectoryOnSuccess doesn't: republishing over an
// --out that already exists (from this function's own prior run, the
// common case in a re-triggered CI job) takes the "*out exists, rename it
// aside to *out.old first" branch rather than the empty-destination one.
func TestCompileRerunLeavesNoBackupDirectory(t *testing.T) {
	outDir := t.TempDir()
	out := filepath.Join(outDir, "out")

	var stdout, stderr bytes.Buffer
	if code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("first run exit code = %d, want 0; stderr: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("second run exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(out + ".old"); !os.IsNotExist(err) {
		t.Errorf("out+\".old\" = %v, want it gone after a successful rerun", err)
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("out+\".tmp\" = %v, want it gone after a successful rerun", err)
	}
	if _, err := os.Stat(filepath.Join(out, "ir", "nodes.jsonl")); err != nil {
		t.Errorf("out/ir/nodes.jsonl: %v, want it present after a successful rerun", err)
	}
}

// TestPublishFromTmpRestoresPreviousOutputOnRenameFailure is a
// regression test for a bug /code-review caught in publishOutput's
// predecessor: if the second rename (tmpOut -> out) failed after the
// first rename (out -> backupOut) had already succeeded, out was left
// missing entirely and the previous good output sat un-restored at
// backupOut - worse than the partial-mix problem the whole two-rename
// scheme exists to prevent.
//
// tmpOut is deliberately never created, so os.Rename(tmpOut, out)
// fails with a real, portable "source does not exist" error - no need
// to contrive a permission or cross-device failure to exercise this
// path.
func TestPublishFromTmpRestoresPreviousOutputOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	backupOut := out + ".old"
	tmpOut := filepath.Join(dir, "out.tmp") // never created

	if err := os.MkdirAll(backupOut, 0o755); err != nil {
		t.Fatalf("create backupOut: %v", err)
	}
	marker := filepath.Join(backupOut, "marker.txt")
	if err := os.WriteFile(marker, []byte("previous output"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	if _, err := publishFromTmp(tmpOut, out, backupOut, true); err == nil {
		t.Fatal("publishFromTmp: got nil error, want an error (tmpOut does not exist, so the rename must fail)")
	}

	if _, err := os.Stat(filepath.Join(out, "marker.txt")); err != nil {
		t.Errorf("out/marker.txt: %v, want the previous output restored to out after the failed publish", err)
	}
	if _, err := os.Stat(backupOut); !os.IsNotExist(err) {
		t.Errorf("backupOut = %v, want it gone (restored back to out), not stranded", err)
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
