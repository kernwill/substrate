package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
)

func TestRunBaselineUpdateWritesApprovalTrail(t *testing.T) {
	dir := t.TempDir()
	currentPath := filepath.Join(dir, "ksi_results.json")
	outPath := filepath.Join(dir, "baseline.json")
	writeIndicatorResults(t, currentPath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "node-1")})

	var stdout, stderr strings.Builder
	code := runBaselineUpdate([]string{"--current", currentPath, "--out", outPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}

	baseline, err := LoadBaseline(outPath)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if baseline.SchemaVersion != baselineSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", baseline.SchemaVersion, baselineSchemaVersion)
	}
	if baseline.ApprovedAt.IsZero() {
		t.Error("ApprovedAt is zero, want a real timestamp")
	}
	if baseline.ApprovedBy == "" {
		t.Error("ApprovedBy is empty, want at least a fallback identity")
	}
	if len(baseline.Results) != 1 || baseline.Results[0].Indicator != "KSI-SVC-SIN" {
		t.Errorf("Results = %+v, want the one indicator from --current", baseline.Results)
	}
}

func TestRunBaselineUpdateRequiresBothFlags(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := runBaselineUpdate(nil, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

// TestBaselineRoundTripsThroughGate exercises the full intended flow -
// baseline update, then gate reading that exact file back - end to end,
// rather than only unit-testing LoadBaseline/runBaselineUpdate in
// isolation.
func TestBaselineRoundTripsThroughGate(t *testing.T) {
	dir := t.TempDir()
	firstRun := filepath.Join(dir, "run1.json")
	secondRun := filepath.Join(dir, "run2.json")
	baselinePath := filepath.Join(dir, "baseline.json")

	writeIndicatorResults(t, firstRun, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "node-1")})
	var out, errOut strings.Builder
	if code := runBaselineUpdate([]string{"--current", firstRun, "--out", baselinePath}, &out, &errOut); code != 0 {
		t.Fatalf("runBaselineUpdate exit code = %d; stderr: %s", code, errOut.String())
	}

	writeIndicatorResults(t, secondRun, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusNotSatisfied)})
	out.Reset()
	errOut.Reset()
	code := runGate([]string{"--baseline", baselinePath, "--current", secondRun}, &out, &errOut)
	if code != 1 {
		t.Fatalf("runGate exit code = %d, want 1; stdout: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "KSI-SVC-SIN") {
		t.Errorf("stdout = %q, want the regression named", out.String())
	}
}
