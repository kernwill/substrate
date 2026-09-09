// Package goldentest is the golden-fixture test harness (T-008): a
// generic mechanism for walking testdata/fixtures/*/, running a
// caller-supplied pipeline against each one, and comparing the result
// against a checked-in expected/ directory. It is framework-agnostic -
// it doesn't know about Terraform, Kubernetes, or FedRAMP - so it's
// meant to serve any future test whose fixture is naturally a
// directory of input files compared against a directory of output
// files (a front-end parser, an IR snapshot, a backend artifact
// emitter), not just "substrate compile".
//
// It is not the only golden-testing pattern in this repo, nor should it
// be: cmd/substrate's rules-show and rules-diff golden tests compare a
// single CLI invocation's stdout against one checked-in text file each
// (testdata/golden/*.txt) - there's no fixture directory of input files
// to walk, so forcing that shape through this package's directory model
// would add indirection without buying anything. Use this package when
// a fixture genuinely is a directory (or will need to become one); a
// single expected-output file next to the test that produces it is
// simpler and is not a gap to close.
//
// Fixtures are this project's regression net (see
// testdata/fixtures/minimal/README.md and CLAUDE.md's "write the golden
// fixture before the parser"), so this package enforces the project's
// two hard rules about them structurally rather than by convention:
//
//   - Regeneration never happens by default. A mismatch against
//     expected/ always fails the test unless the caller explicitly
//     passes update=true.
//   - Regeneration is never silent. Every file (re)written is logged via
//     t.Logf, so a test run that regenerated fixtures says so in its own
//     output - a human still has to run `git diff` and read it, per
//     CLAUDE.md's "review the diff, because that diff is a change in
//     what we assert to the federal government," but at least the test
//     output itself never hides that a write happened.
package goldentest

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Runner produces one fixture's actual output as a set of named
// artifacts (a relative path, using "/" separators, mapped to file
// content) given that fixture's directory. What counts as an artifact is
// entirely up to the caller: files written to a "--out" directory,
// captured stdout/stderr, an exit code, or any combination - Run only
// ever compares byte-for-byte against files of the same names under
// <fixtureDir>/expected/.
type Runner func(t *testing.T, fixtureDir string) map[string][]byte

// Run walks fixturesDir for immediate subdirectories - each one a single
// fixture - and, for each, calls runner and compares the result against
// <fixtureDir>/expected/.
//
// update controls regeneration (wire it to an env var or flag; false is
// the only safe default - see the package doc). When false, any
// difference from expected/ - a changed artifact, a new one runner
// produced that expected/ doesn't have, or one expected/ has that runner
// no longer produces - fails that fixture's subtest. When true,
// expected/ is rewritten to match runner's current output exactly
// (stale entries are removed), and every write is logged.
func Run(t *testing.T, fixturesDir string, update bool, runner Runner) {
	t.Helper()
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatalf("goldentest: read fixtures dir %s: %v", fixturesDir, err)
	}

	found := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		found++
		fixtureDir := filepath.Join(fixturesDir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			runFixture(t, fixtureDir, update, runner)
		})
	}
	if found == 0 {
		t.Fatalf("goldentest: no fixture directories found under %s", fixturesDir)
	}
}

func runFixture(t *testing.T, fixtureDir string, update bool, runner Runner) {
	t.Helper()
	expectedDir := filepath.Join(fixtureDir, "expected")
	actual := runner(t, fixtureDir)

	if update {
		regenerate(t, expectedDir, actual)
		return
	}

	want := readExpected(t, expectedDir)
	compare(t, actual, want)
}

// regenerate replaces expectedDir's contents with actual, logging every
// write (and every removal of a stale entry) so this is never silent
// even though it was explicitly requested.
func regenerate(t *testing.T, expectedDir string, actual map[string][]byte) {
	t.Helper()
	before := readExpected(t, expectedDir)

	if err := os.RemoveAll(expectedDir); err != nil {
		t.Fatalf("goldentest: clear %s: %v", expectedDir, err)
	}
	for _, name := range sortedKeys(actual) {
		dst := filepath.Join(expectedDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("goldentest: mkdir for %s: %v", dst, err)
		}
		if err := os.WriteFile(dst, actual[name], 0o644); err != nil {
			t.Fatalf("goldentest: write %s: %v", dst, err)
		}
		t.Logf("goldentest: wrote %s", dst)
	}
	for _, name := range sortedKeys(before) {
		if _, ok := actual[name]; !ok {
			t.Logf("goldentest: removed stale %s", filepath.Join(expectedDir, filepath.FromSlash(name)))
		}
	}
}

// readExpected reads every file under expectedDir into a map keyed by
// its slash-separated path relative to expectedDir. A missing
// expectedDir (a fixture with no expected/ yet) reads as empty, not an
// error - that's the state a brand-new fixture is in before its first
// deliberate regeneration.
func readExpected(t *testing.T, expectedDir string) map[string][]byte {
	t.Helper()
	want := map[string][]byte{}
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		return want
	}
	err := filepath.WalkDir(expectedDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(expectedDir, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		want[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatalf("goldentest: read %s: %v", expectedDir, err)
	}
	return want
}

func compare(t *testing.T, actual, want map[string][]byte) {
	t.Helper()
	for _, d := range compareArtifacts(actual, want) {
		t.Errorf("goldentest: %s", d)
	}
}

// compareArtifacts returns a human-readable description of every
// mismatch between actual and want, sorted by artifact name. An empty
// result means actual exactly matches want. Kept as a plain function
// (not driven by *testing.T) so its logic - including the "produced but
// unrecorded" and "recorded but unproduced" cases - can be unit tested
// directly, without the awkwardness of asserting that a *testing.T-based
// call correctly reported a failure (a subtest failure would propagate
// up and fail whatever test triggered it).
func compareArtifacts(actual, want map[string][]byte) []string {
	names := map[string]bool{}
	for n := range actual {
		names[n] = true
	}
	for n := range want {
		names[n] = true
	}
	var diffs []string
	for _, name := range sortedKeys(names) {
		a, aok := actual[name]
		w, wok := want[name]
		switch {
		case aok && !wok:
			diffs = append(diffs, name+": produced but not recorded in expected/ (regenerate deliberately to add it)\n--- got ---\n"+string(a))
		case !aok && wok:
			diffs = append(diffs, name+": recorded in expected/ but not produced this run")
		case !bytes.Equal(a, w):
			diffs = append(diffs, name+": does not match expected/\n--- got ---\n"+string(a)+"\n--- want ---\n"+string(w))
		}
	}
	return diffs
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
