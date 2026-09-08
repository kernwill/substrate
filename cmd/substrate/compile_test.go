package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
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
	update := *updateGolden || os.Getenv("SUBSTRATE_UPDATE_GOLDEN") != ""
	goldentest.Run(t, "../../testdata/fixtures", update, runCompileFixture)
}

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
