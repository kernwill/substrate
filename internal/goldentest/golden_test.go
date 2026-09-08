package goldentest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// --- compareArtifacts: pure logic, the bulk of the correctness surface ---

func TestCompareArtifactsMatch(t *testing.T) {
	actual := map[string][]byte{"a.txt": []byte("hello")}
	want := map[string][]byte{"a.txt": []byte("hello")}
	if diffs := compareArtifacts(actual, want); len(diffs) != 0 {
		t.Errorf("compareArtifacts(match) = %v, want no diffs", diffs)
	}
}

func TestCompareArtifactsDetectsChanged(t *testing.T) {
	actual := map[string][]byte{"a.txt": []byte("hello")}
	want := map[string][]byte{"a.txt": []byte("goodbye")}
	diffs := compareArtifacts(actual, want)
	if len(diffs) != 1 {
		t.Fatalf("compareArtifacts(changed) = %v, want exactly 1 diff", diffs)
	}
	if !strings.Contains(diffs[0], "does not match expected/") {
		t.Errorf("diff = %q, want it to describe a mismatch", diffs[0])
	}
}

func TestCompareArtifactsDetectsUnrecorded(t *testing.T) {
	actual := map[string][]byte{"a.txt": []byte("hello")}
	want := map[string][]byte{}
	diffs := compareArtifacts(actual, want)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "produced but not recorded") {
		t.Errorf("compareArtifacts(unrecorded) = %v, want one \"produced but not recorded\" diff", diffs)
	}
}

func TestCompareArtifactsDetectsMissing(t *testing.T) {
	actual := map[string][]byte{}
	want := map[string][]byte{"a.txt": []byte("hello")}
	diffs := compareArtifacts(actual, want)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "recorded in expected/ but not produced") {
		t.Errorf("compareArtifacts(missing) = %v, want one \"not produced\" diff", diffs)
	}
}

func TestCompareArtifactsMultipleFilesIndependently(t *testing.T) {
	actual := map[string][]byte{
		"same.txt":    []byte("x"),
		"changed.txt": []byte("new"),
		"new.txt":     []byte("added"),
	}
	want := map[string][]byte{
		"same.txt":    []byte("x"),
		"changed.txt": []byte("old"),
		"gone.txt":    []byte("was here"),
	}
	diffs := compareArtifacts(actual, want)
	if len(diffs) != 3 {
		t.Fatalf("compareArtifacts = %v, want exactly 3 diffs (changed, new, gone)", diffs)
	}
}

// --- readExpected: reading expected/ off disk ---

func TestReadExpectedMissingDirReadsEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	got := readExpected(t, dir)
	if len(got) != 0 {
		t.Errorf("readExpected(missing dir) = %v, want empty", got)
	}
}

func TestReadExpectedReadsNestedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "top.txt"), "top")
	writeFile(t, filepath.Join(dir, "sub", "nested.txt"), "nested")

	got := readExpected(t, dir)
	if string(got["top.txt"]) != "top" {
		t.Errorf(`got["top.txt"] = %q, want "top"`, got["top.txt"])
	}
	if string(got["sub/nested.txt"]) != "nested" {
		t.Errorf(`got["sub/nested.txt"] = %q, want "nested"`, got["sub/nested.txt"])
	}
	if len(got) != 2 {
		t.Errorf("readExpected returned %d entries, want 2", len(got))
	}
}

// --- regenerate: the update=true write path, and that it never happens implicitly ---

func TestRegenerateWritesActualOutput(t *testing.T) {
	dir := t.TempDir()
	expectedDir := filepath.Join(dir, "expected")

	regenerate(t, expectedDir, map[string][]byte{"a.txt": []byte("hello")})

	got := readExpected(t, expectedDir)
	if string(got["a.txt"]) != "hello" {
		t.Errorf(`after regenerate, expected/a.txt = %q, want "hello"`, got["a.txt"])
	}
}

func TestRegenerateRemovesStaleEntries(t *testing.T) {
	dir := t.TempDir()
	expectedDir := filepath.Join(dir, "expected")
	writeFile(t, filepath.Join(expectedDir, "stale.txt"), "old and unused")

	regenerate(t, expectedDir, map[string][]byte{"a.txt": []byte("hello")})

	got := readExpected(t, expectedDir)
	if _, ok := got["stale.txt"]; ok {
		t.Error("regenerate left a stale entry (stale.txt) that the current run no longer produces")
	}
	if len(got) != 1 {
		t.Errorf("expected/ has %d entries after regenerate, want exactly 1", len(got))
	}
}

// --- Run: the *testing.T-driving entry point, exercised on its safe (passing) path ---

func TestRunPassesWhenActualMatchesExpected(t *testing.T) {
	fixturesRoot := t.TempDir()
	fixtureDir := filepath.Join(fixturesRoot, "case1")
	writeFile(t, filepath.Join(fixtureDir, "expected", "out.txt"), "expected output")

	Run(t, fixturesRoot, false, func(t *testing.T, dir string) map[string][]byte {
		if dir != fixtureDir {
			t.Errorf("runner called with fixtureDir = %q, want %q", dir, fixtureDir)
		}
		return map[string][]byte{"out.txt": []byte("expected output")}
	})
	// If Run incorrectly reported a mismatch here, this test itself
	// would fail - t.Run's failures propagate to the parent - so
	// reaching this point at all is the assertion.
}

func TestRunVisitsEveryFixtureSubdirectory(t *testing.T) {
	fixturesRoot := t.TempDir()
	for _, name := range []string{"case1", "case2", "case3"} {
		writeFile(t, filepath.Join(fixturesRoot, name, "expected", "out.txt"), name)
	}

	visited := map[string]bool{}
	Run(t, fixturesRoot, false, func(t *testing.T, dir string) map[string][]byte {
		name := filepath.Base(dir)
		visited[name] = true
		return map[string][]byte{"out.txt": []byte(name)}
	})

	for _, name := range []string{"case1", "case2", "case3"} {
		if !visited[name] {
			t.Errorf("Run did not visit fixture %q", name)
		}
	}
}

func TestRunUpdateRegeneratesRatherThanFailing(t *testing.T) {
	fixturesRoot := t.TempDir()
	fixtureDir := filepath.Join(fixturesRoot, "case1")
	// The fixture directory itself exists, but has no expected/ yet - a
	// brand-new fixture that has never been regenerated.
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", fixtureDir, err)
	}

	Run(t, fixturesRoot, true, func(t *testing.T, dir string) map[string][]byte {
		return map[string][]byte{"out.txt": []byte("freshly generated")}
	})

	got := readExpected(t, filepath.Join(fixtureDir, "expected"))
	if string(got["out.txt"]) != "freshly generated" {
		t.Errorf(`expected/out.txt = %q, want "freshly generated"`, got["out.txt"])
	}
}
