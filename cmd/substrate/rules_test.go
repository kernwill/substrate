package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/kernwill/substrate/internal/rules"
)

var updateGolden = flag.Bool("update", false, "update golden files")

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
			if *updateGolden {
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
	ds := testDataset(t)
	var stdout, stderr bytes.Buffer
	code := runRules(ds, nil, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestRulesUnknownSubcommand(t *testing.T) {
	ds := testDataset(t)
	var stdout, stderr bytes.Buffer
	code := runRules(ds, []string{"diff"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2 (rules diff is T-007, not implemented yet)", code)
	}
}
