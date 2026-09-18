package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

func result(indicator string, status fedramp20x.Status, evidence ...string) fedramp20x.IndicatorResult {
	return fedramp20x.IndicatorResult{Indicator: indicator, Family: "SVC", Status: status, Reason: "test", Evidence: evidence}
}

func mustDiffResults(t *testing.T, baseline, current []fedramp20x.IndicatorResult, nodesByID map[ir.NodeID]ir.Node) gateDiff {
	t.Helper()
	diff, err := diffResults(baseline, current, nodesByID)
	if err != nil {
		t.Fatalf("diffResults: %v", err)
	}
	return diff
}

func TestDiffResultsDetectsRegression(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "node-1")}
	current := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusUndetermined)}

	diff := mustDiffResults(t, baseline, current, nil)
	if len(diff.Regressions) != 1 {
		t.Fatalf("got %d regressions, want 1", len(diff.Regressions))
	}
	r := diff.Regressions[0]
	if r.Indicator != "KSI-SVC-SIN" || r.BaselineStatus != fedramp20x.StatusSatisfied || r.CurrentStatus != fedramp20x.StatusUndetermined {
		t.Errorf("regression = %+v, want KSI-SVC-SIN satisfied->undetermined", r)
	}
}

func TestDiffResultsDetectsImprovement(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusUndetermined)}
	current := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "node-1")}

	diff := mustDiffResults(t, baseline, current, nil)
	if len(diff.Regressions) != 0 {
		t.Errorf("got %d regressions, want 0 (this is an improvement, not a regression)", len(diff.Regressions))
	}
	if len(diff.Improvements) != 1 {
		t.Fatalf("got %d improvements, want 1", len(diff.Improvements))
	}
}

// TestDiffResultsUndeterminedToUndeterminedIsNotARegression confirms
// the near-universal real-world case (an indicator staying
// undetermined, even if its reason text changes because different
// controls are now missing) is never treated as a regression - neither
// state was ever a real compliance signal to begin with.
func TestDiffResultsUndeterminedToUndeterminedIsNotARegression(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{{Indicator: "KSI-SVC-SIN", Status: fedramp20x.StatusUndetermined, Reason: "missing A"}}
	current := []fedramp20x.IndicatorResult{{Indicator: "KSI-SVC-SIN", Status: fedramp20x.StatusUndetermined, Reason: "missing B"}}

	diff := mustDiffResults(t, baseline, current, nil)
	if len(diff.Regressions) != 0 {
		t.Errorf("got %d regressions, want 0", len(diff.Regressions))
	}
	if diff.Unchanged != 1 {
		t.Errorf("Unchanged = %d, want 1", diff.Unchanged)
	}
}

func TestDiffResultsNewIndicatorIsNeverARegression(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{}
	current := []fedramp20x.IndicatorResult{result("KSI-NEW-ABC", fedramp20x.StatusUndetermined)}

	diff := mustDiffResults(t, baseline, current, nil)
	if len(diff.Regressions) != 0 {
		t.Errorf("got %d regressions, want 0 (a brand new indicator cannot have regressed)", len(diff.Regressions))
	}
	if len(diff.New) != 1 || diff.New[0] != "KSI-NEW-ABC" {
		t.Errorf("New = %v, want [KSI-NEW-ABC]", diff.New)
	}
}

func TestDiffResultsMissingIndicatorIsReportedNotFailed(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{result("KSI-GONE-XYZ", fedramp20x.StatusSatisfied)}
	current := []fedramp20x.IndicatorResult{}

	diff := mustDiffResults(t, baseline, current, nil)
	if len(diff.Regressions) != 0 {
		t.Errorf("got %d regressions, want 0 (missing is reported separately, not as a regression)", len(diff.Regressions))
	}
	if len(diff.Missing) != 1 || diff.Missing[0] != "KSI-GONE-XYZ" {
		t.Errorf("Missing = %v, want [KSI-GONE-XYZ]", diff.Missing)
	}
}

// TestDiffResultsSatisfiedToNotApplicableIsNotARegression is a
// regression test: an earlier version of diffResults treated ANY
// transition away from Satisfied as a gate failure, including to
// NotApplicable - which just means the control's own scope changed
// (e.g. the resource it was about was removed), not that anything got
// worse. Failing the gate over this would be a false positive eroding
// trust in every other real regression it reports.
func TestDiffResultsSatisfiedToNotApplicableIsNotARegression(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "node-1")}
	current := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusNotApplicable)}

	diff := mustDiffResults(t, baseline, current, nil)
	if len(diff.Regressions) != 0 {
		t.Errorf("got %d regressions, want 0 (satisfied->not_applicable is a scope change, not a regression)", len(diff.Regressions))
	}
	if len(diff.OtherChanges) != 1 {
		t.Fatalf("got %d OtherChanges, want 1", len(diff.OtherChanges))
	}
}

// TestDiffResultsRejectsDuplicateIndicatorID is a regression test: an
// earlier version built its lookup maps via plain assignment, silently
// keeping only the last entry for a duplicate Indicator ID rather than
// erroring - making the gate's pass/fail decision depend on slice
// order for what should be a loud data-integrity failure.
func TestDiffResultsRejectsDuplicateIndicatorID(t *testing.T) {
	baseline := []fedramp20x.IndicatorResult{
		result("KSI-SVC-SIN", fedramp20x.StatusSatisfied),
		result("KSI-SVC-SIN", fedramp20x.StatusUndetermined),
	}
	current := []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)}

	if _, err := diffResults(baseline, current, nil); err == nil {
		t.Fatal("diffResults: got nil error, want an error naming the duplicate indicator")
	}
}

func TestLocationsForResolvesAndDedupesNodeIDs(t *testing.T) {
	nodesByID := map[ir.NodeID]ir.Node{
		"node-1": {ID: "node-1", Provenance: provenance.Record{Locator: provenance.Locator{Path: "main.tf", Line: 10}}},
		"node-2": {ID: "node-2", Provenance: provenance.Record{Locator: provenance.Locator{Path: "main.tf", Line: 10}}},
		"node-3": {ID: "node-3", Provenance: provenance.Record{Locator: provenance.Locator{Path: "other.tf", Line: 5}}},
	}
	got := locationsFor([]string{"node-1", "node-2", "node-3", "node-missing"}, nodesByID)
	want := []string{"main.tf:10", "other.tf:5"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func writeIndicatorResults(t *testing.T, path string, results []fedramp20x.IndicatorResult) {
	t.Helper()
	raw, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeTestBaseline(t *testing.T, path string, results []fedramp20x.IndicatorResult) {
	t.Helper()
	b := Baseline{SchemaVersion: baselineSchemaVersion, ApprovedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ApprovedBy: "test", Results: results}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRunGateExitsOneOnRegressionWithDefaultSeverity(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	currentPath := filepath.Join(dir, "current.json")
	writeTestBaseline(t, baselinePath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)})
	writeIndicatorResults(t, currentPath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusUndetermined)})

	var stdout, stderr strings.Builder
	code := runGate([]string{"--baseline", baselinePath, "--current", currentPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "KSI-SVC-SIN") {
		t.Errorf("stdout = %q, want it to name the regressed indicator", stdout.String())
	}
}

func TestRunGateWarnSeverityExitsZeroOnRegression(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	currentPath := filepath.Join(dir, "current.json")
	writeTestBaseline(t, baselinePath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)})
	writeIndicatorResults(t, currentPath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusUndetermined)})

	var stdout, stderr strings.Builder
	code := runGate([]string{"--baseline", baselinePath, "--current", currentPath, "--severity", "warn"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (warn severity must never fail the gate); stdout: %s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "KSI-SVC-SIN") {
		t.Errorf("stdout = %q, want the regression still reported even though it doesn't fail the gate", stdout.String())
	}
}

func TestRunGateExitsZeroWhenClean(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	currentPath := filepath.Join(dir, "current.json")
	writeTestBaseline(t, baselinePath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)})
	writeIndicatorResults(t, currentPath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)})

	var stdout, stderr strings.Builder
	code := runGate([]string{"--baseline", baselinePath, "--current", currentPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
}

func TestRunGateRejectsInvalidSeverity(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	currentPath := filepath.Join(dir, "current.json")
	writeTestBaseline(t, baselinePath, nil)
	writeIndicatorResults(t, currentPath, nil)

	var stdout, stderr strings.Builder
	code := runGate([]string{"--baseline", baselinePath, "--current", currentPath, "--severity", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

func TestRunGateResolvesEvidenceLocationsFromNodesFile(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	currentPath := filepath.Join(dir, "current.json")
	nodesPath := filepath.Join(dir, "nodes.jsonl")

	writeTestBaseline(t, baselinePath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "terraform:aws_s3_bucket_versioning.example")})
	writeIndicatorResults(t, currentPath, []fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusUndetermined)})

	node := ir.Node{
		ID:            "terraform:aws_s3_bucket_versioning.example",
		ControlFamily: "CP",
		Kind:          "s3_bucket_versioning",
		Provenance:    provenance.Record{Locator: provenance.Locator{Path: "main.tf", Line: 15}},
		SchemaVersion: ir.SchemaVersion,
	}
	f, err := os.Create(nodesPath)
	if err != nil {
		t.Fatalf("create nodes.jsonl: %v", err)
	}
	if err := ir.WriteNodesJSONL(f, []ir.Node{node}); err != nil {
		t.Fatalf("write nodes.jsonl: %v", err)
	}
	f.Close()

	var stdout, stderr strings.Builder
	code := runGate([]string{"--baseline", baselinePath, "--current", currentPath, "--nodes", nodesPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "main.tf:15") {
		t.Errorf("stdout = %q, want it to name main.tf:15 as where the regressed indicator's prior evidence was", stdout.String())
	}
}

// The Test*GateComment* tests below exercise the GitHub REST client
// against an httptest.Server rather than the real API - no network
// dependency, no token needed - by calling (*githubConfig).postGateComment
// directly with apiBase pointed at the test server.

func testRegressionDiff(t *testing.T) gateDiff {
	t.Helper()
	return mustDiffResults(t,
		[]fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied, "node-1")},
		[]fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusUndetermined)},
		nil,
	)
}

func TestPostGateCommentCreatesNewCommentWhenNoneMarked(t *testing.T) {
	var createCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			createCalled = true
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if !strings.Contains(body["body"], gateCommentMarker) {
				t.Errorf("posted comment body missing marker: %q", body["body"])
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id": 1}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := &githubConfig{apiBase: srv.URL, token: "test-token", owner: "acme", repo: "widgets", prNumber: 7}
	if err := cfg.postGateComment(context.Background(), testRegressionDiff(t)); err != nil {
		t.Fatalf("postGateComment: %v", err)
	}
	if !createCalled {
		t.Error("expected a POST to create a new comment, none was made")
	}
}

func TestPostGateCommentUpdatesExistingMarkedComment(t *testing.T) {
	var patchCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id": 42, "body": "old ` + gateCommentMarker + `"}]`))
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/issues/comments/42"):
			patchCalled = true
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 42}`))
		case r.Method == http.MethodPost:
			t.Error("expected an update (PATCH) of the existing comment, not a new POST")
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := &githubConfig{apiBase: srv.URL, token: "test-token", owner: "acme", repo: "widgets", prNumber: 7}
	if err := cfg.postGateComment(context.Background(), testRegressionDiff(t)); err != nil {
		t.Fatalf("postGateComment: %v", err)
	}
	if !patchCalled {
		t.Error("expected a PATCH to update the existing comment, none was made")
	}
}

// TestPostGateCommentSkipsWhenCleanAndNothingPreviouslyPosted confirms
// a green run with no prior marked comment never touches the PR at all
// - no informational value in creating a "no regressions" comment
// nobody asked to see.
func TestPostGateCommentSkipsWhenCleanAndNothingPreviouslyPosted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected request: %s %s (a clean run with no prior comment should only ever list, never create/update)", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cleanDiff := mustDiffResults(t,
		[]fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)},
		[]fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)},
		nil,
	)
	cfg := &githubConfig{apiBase: srv.URL, token: "test-token", owner: "acme", repo: "widgets", prNumber: 7}
	if err := cfg.postGateComment(context.Background(), cleanDiff); err != nil {
		t.Fatalf("postGateComment: %v", err)
	}
}

// TestPostGateCommentUpdatesStaleCommentWhenResolved is a regression
// test: an earlier version only ever called postGateComment when
// diff.Regressions was non-empty, so a run that fixed a previously-
// reported regression never updated the PR at all - the stale
// "regression found" comment from the earlier run sat there forever.
// Now: a clean run with an existing marked comment must update it to
// say the regression is resolved, not skip.
func TestPostGateCommentUpdatesStaleCommentWhenResolved(t *testing.T) {
	var patchedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id": 42, "body": "1 regression(s) found ` + gateCommentMarker + `"}]`))
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/issues/comments/42"):
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			patchedBody = body["body"]
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 42}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cleanDiff := mustDiffResults(t,
		[]fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)},
		[]fedramp20x.IndicatorResult{result("KSI-SVC-SIN", fedramp20x.StatusSatisfied)},
		nil,
	)
	cfg := &githubConfig{apiBase: srv.URL, token: "test-token", owner: "acme", repo: "widgets", prNumber: 7}
	if err := cfg.postGateComment(context.Background(), cleanDiff); err != nil {
		t.Fatalf("postGateComment: %v", err)
	}
	if patchedBody == "" {
		t.Fatal("expected a PATCH updating the stale comment, none was made")
	}
	if !strings.Contains(patchedBody, "resolved") {
		t.Errorf("patched body = %q, want it to say the regression is resolved", patchedBody)
	}
}

// TestFindMarkedCommentPaginates is a regression test: an earlier
// version of findMarkedComment fetched only GitHub's default 30-comment
// first page, so a marked comment posted several runs ago on an active
// PR (more than ~30 comments deep) was never found, and every
// subsequent run created a duplicate instead of updating in place. This
// forces a marked comment onto a second page and confirms it's still
// found.
func TestFindMarkedCommentPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/issues/7/comments") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "1":
			// A full first page of unrelated comments - exactly
			// githubCommentsPerPage of them, so the client knows to
			// request a second page.
			comments := make([]string, githubCommentsPerPage)
			for i := range comments {
				comments[i] = fmt.Sprintf(`{"id": %d, "body": "unrelated comment %d"}`, i+1, i+1)
			}
			w.Write([]byte("[" + strings.Join(comments, ",") + "]"))
		case "2":
			w.Write([]byte(`[{"id": 999, "body": "the marked one ` + gateCommentMarker + `"}]`))
		default:
			t.Errorf("unexpected page: %s", r.URL.Query().Get("page"))
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	cfg := &githubConfig{apiBase: srv.URL, token: "test-token", owner: "acme", repo: "widgets", prNumber: 7}
	id, found, err := cfg.findMarkedComment(context.Background())
	if err != nil {
		t.Fatalf("findMarkedComment: %v", err)
	}
	if !found {
		t.Fatal("findMarkedComment: got found=false, want the marked comment on page 2 to be found")
	}
	if id != 999 {
		t.Errorf("id = %d, want 999", id)
	}
}
