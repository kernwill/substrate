package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kernwill/substrate/internal/rules"
)

const vendoredDatasetPathForCLI = "../../internal/rules/data/fedramp-consolidated-rules.json"

func testDataset(t *testing.T) *rules.Dataset {
	t.Helper()
	ds, err := rules.Default()
	if err != nil {
		t.Fatalf("rules.Default(): %v", err)
	}
	return ds
}

// TestGoldenRulesShow runs "substrate rules show" against the real
// vendored dataset with a representative set of --class/--type/--path
// combinations and diffs stdout against a checked-in fixture (T-005's
// "the command has a golden test"). Regenerate with:
//
//	go test ./cmd/substrate -run TestGoldenRulesShow -update
//
// then review the diff before committing - a fixture diff here is a
// change in what the CLI asserts is true about the certified dataset.
func TestGoldenRulesShow(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"class_a", []string{"--class", "A"}},
		{"class_c", []string{"--class", "C"}},
		{"type_rev5_path_agency", []string{"--type", "Rev5", "--path", "Agency"}},
		{"class_a_include_placeholder", []string{"--class", "A", "--include-placeholder"}},
	}

	ds := testDataset(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runRulesShow(ds, c.args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}

			golden := filepath.Join("testdata", "golden", "rules_show_"+c.name+".txt")
			if goldenUpdateRequested() {
				if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
					t.Fatalf("write golden file: %v", err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden file %s (run with -update to create it): %v", golden, err)
			}
			if stdout.String() != string(want) {
				t.Errorf("output for %v does not match %s\n--- got ---\n%s--- want ---\n%s", c.args, golden, stdout.String(), string(want))
			}
		})
	}
}

// TestGoldenRulesDiff runs "substrate rules diff" against two small,
// hand-authored fixture files (testdata/diff/a.json, b.json - not the
// real vendored dataset, so the fixture stays small and every change in
// it is reviewable) covering one added, one removed, and one modified
// record in each of FRD, FRR, KSI, and CTL, and diffs stdout against a
// checked-in golden fixture (T-007's "with tests" / "correct structured
// output"). Regenerate with:
//
//	go test ./cmd/substrate -run TestGoldenRulesDiff -update
func TestGoldenRulesDiff(t *testing.T) {
	fileA := filepath.Join("testdata", "diff", "a.json")
	fileB := filepath.Join("testdata", "diff", "b.json")

	cases := []struct {
		name string
		args []string
	}{
		{"text", []string{fileA, fileB}},
		{"json", []string{"--format", "json", fileA, fileB}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runRulesDiff(c.args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
			}

			golden := filepath.Join("testdata", "golden", "rules_diff_"+c.name+".txt")
			if goldenUpdateRequested() {
				if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
					t.Fatalf("write golden file: %v", err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden file %s (run with -update to create it): %v", golden, err)
			}
			if stdout.String() != string(want) {
				t.Errorf("output for %v does not match %s\n--- got ---\n%s--- want ---\n%s", c.args, golden, stdout.String(), string(want))
			}
		})
	}
}

func TestRulesDiffIdenticalFileProducesNoEntries(t *testing.T) {
	fileA := filepath.Join("testdata", "diff", "a.json")
	var stdout, stderr bytes.Buffer
	code := runRulesDiff([]string{fileA, fileA}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("0 added, 0 removed, 0 modified")) {
		t.Errorf("diffing a file against itself: stdout = %q, want a 0/0/0 summary", stdout.String())
	}
}

func TestRulesDiffRejectsWrongArgCount(t *testing.T) {
	fileA := filepath.Join("testdata", "diff", "a.json")
	var stdout, stderr bytes.Buffer
	code := runRulesDiff([]string{fileA}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRulesDiffRejectsInvalidFormat(t *testing.T) {
	fileA := filepath.Join("testdata", "diff", "a.json")
	fileB := filepath.Join("testdata", "diff", "b.json")
	var stdout, stderr bytes.Buffer
	code := runRulesDiff([]string{"--format", "yaml", fileA, fileB}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

// TestRulesDiffFormatFlagWorksInAnyPosition is a regression test for a
// bug the code review's ultra pass found: stdlib flag.FlagSet.Parse
// stops at the first non-flag argument, so a naturally-typed invocation
// like "diff a.json b.json --format json" (flag after the positionals)
// silently misparsed as four positional arguments instead of two plus a
// flag. runRulesDiff now parses arguments by hand instead of via flag.FlagSet.
func TestRulesDiffFormatFlagWorksInAnyPosition(t *testing.T) {
	fileA := filepath.Join("testdata", "diff", "a.json")
	fileB := filepath.Join("testdata", "diff", "b.json")

	cases := [][]string{
		{"--format", "json", fileA, fileB},
		{fileA, fileB, "--format", "json"},
		{fileA, "--format", "json", fileB},
		{"--format=json", fileA, fileB},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := runRulesDiff(args, &stdout, &stderr)
		if code != 0 {
			t.Errorf("runRulesDiff(%v): exit code = %d, stderr = %s", args, code, stderr.String())
			continue
		}
		if !bytes.Contains(stdout.Bytes(), []byte(`"from_version"`)) {
			t.Errorf("runRulesDiff(%v): stdout does not look like JSON output: %s", args, stdout.String())
		}
	}
}

func TestRulesDiffRejectsMissingFile(t *testing.T) {
	fileA := filepath.Join("testdata", "diff", "a.json")
	var stdout, stderr bytes.Buffer
	code := runRulesDiff([]string{fileA, "does-not-exist.json"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRulesDiffAgainstVendoredDataset(t *testing.T) {
	// The vendored dataset diffed against itself, via the real CLI path
	// (file load + schema validation + diff), not just the in-package
	// DiffDatasets unit tests.
	var stdout, stderr bytes.Buffer
	code := runRulesDiff([]string{vendoredDatasetPathForCLI, vendoredDatasetPathForCLI}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("0 added, 0 removed, 0 modified")) {
		t.Errorf("stdout = %q, want a 0/0/0 summary", stdout.String())
	}
}

func TestRulesShowRejectsInvalidClass(t *testing.T) {
	ds := testDataset(t)
	var stdout, stderr bytes.Buffer
	code := runRulesShow(ds, []string{"--class", "Z"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on a usage error", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a message naming the bad --class value")
	}
}

func TestRulesShowRejectsInvalidType(t *testing.T) {
	ds := testDataset(t)
	var stdout, stderr bytes.Buffer
	code := runRulesShow(ds, []string{"--type", "20y"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRulesShowRejectsInvalidPath(t *testing.T) {
	ds := testDataset(t)
	var stdout, stderr bytes.Buffer
	code := runRulesShow(ds, []string{"--path", "Nowhere"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRulesShowDefaultExcludesPlaceholderDoc(t *testing.T) {
	ds := testDataset(t)
	var stdout, stderr bytes.Buffer
	if code := runRulesShow(ds, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("AGU-")) {
		t.Error("default output (no --include-placeholder) contains an AGU rule, but AGU's document status is \"placeholder\"")
	}
}

func TestRulesNoSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runRules(nil, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRulesUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runRules([]string{"gate"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (rules gate is not a thing; gate is a separate top-level command, not implemented yet)", code)
	}
}
