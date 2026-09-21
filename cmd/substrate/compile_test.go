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
	"time"

	"github.com/kernwill/substrate/internal/backends/fedramp20x"
	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
	oktacollectors "github.com/kernwill/substrate/internal/frontend/collectors/okta"
	"github.com/kernwill/substrate/internal/goldentest"
	"github.com/kernwill/substrate/internal/provenance"
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

// TestCompileIngestsRuntimeEvidence exercises --runtime end to end:
// collect.go's own writeCollectOutput builds a real "collect" output
// directory (rather than hand-writing aws_s3.json/aws_iam.json, so this
// test also stays honest if that format ever changes), and runCompile
// is pointed at it via --runtime. The resulting evidence graph must
// contain the AWS-mapped node the synthetic bucket's resolved encryption
// fact produces, merged in alongside the three static frontends' - and
// omitting --runtime (the default, exercised by every other test in
// this file and by TestGoldenCompile) must produce no such node at all.
func TestCompileIngestsRuntimeEvidence(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	s3Graph := &awscollectors.S3Graph{Buckets: []awscollectors.Bucket{{
		Name: "runtime-evidence-bucket",
		Encryption: &awscollectors.BucketEncryption{
			Algorithm: "aws:kms",
			Provenance: provenance.Record{
				SourceType:       "aws",
				Locator:          provenance.Locator{API: "s3:GetBucketEncryption", Parameters: map[string]string{"bucket": "runtime-evidence-bucket"}},
				Timestamp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				CollectorVersion: awscollectors.S3CollectorVersion,
				Basis:            provenance.Observed,
				Confidence:       provenance.Deterministic,
			},
		},
	}}}
	iamGraph := &awscollectors.IAMGraph{}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{}
	securityGroupsGraph := &awscollectors.SecurityGroupsGraph{}
	if _, err := writeCollectOutput(runtimeDir, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, nil); err != nil {
		t.Fatalf("writeCollectOutput: %v", err)
	}

	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out, "--runtime", runtimeDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCompile exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ingested runtime evidence for 1 s3 bucket(s), 0 iam user(s), 0 cloudtrail trail(s), and 0 security group rule(s)") {
		t.Errorf("stdout = %q, want it to mention the ingested runtime evidence counts", stdout.String())
	}

	nodesRaw, err := os.ReadFile(filepath.Join(out, "ir", "nodes.jsonl"))
	if err != nil {
		t.Fatalf("read nodes.jsonl: %v", err)
	}
	if !strings.Contains(string(nodesRaw), "runtime-evidence-bucket") {
		t.Errorf("nodes.jsonl does not mention runtime-evidence-bucket; --runtime evidence was not merged into the graph")
	}
}

// TestCompileIngestsOktaRuntimeEvidence mirrors
// TestCompileIngestsRuntimeEvidence for Okta evidence (FR-3.9): a
// --runtime directory with all four okta_*.json artifacts present must
// have their nodes merged into the evidence graph too, alongside AWS's.
func TestCompileIngestsOktaRuntimeEvidence(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	s3Graph := &awscollectors.S3Graph{}
	iamGraph := &awscollectors.IAMGraph{}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{}
	securityGroupsGraph := &awscollectors.SecurityGroupsGraph{}
	oktaGraphs := &oktaResults{
		MFA: &oktacollectors.MFAEnrollmentGraph{Policies: []oktacollectors.MFAEnrollmentPolicy{{
			ID:     "runtime-evidence-policy",
			Status: "ACTIVE",
			Provenance: provenance.Record{
				SourceType:       "okta",
				Locator:          provenance.Locator{API: "okta:ListPolicies:MFA_ENROLL", Parameters: map[string]string{"policy_id": "runtime-evidence-policy"}},
				Timestamp:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				CollectorVersion: oktacollectors.MFACollectorVersion,
				Basis:            provenance.Observed,
				Confidence:       provenance.Deterministic,
			},
		}}},
		SessionPolicy: &oktacollectors.SessionPolicyGraph{},
		Provisioning:  &oktacollectors.ProvisioningEventGraph{},
		AdminRole:     &oktacollectors.AdminRoleAssignmentGraph{},
	}
	if _, err := writeCollectOutput(runtimeDir, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, oktaGraphs); err != nil {
		t.Fatalf("writeCollectOutput: %v", err)
	}

	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out, "--runtime", runtimeDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCompile exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ingested okta runtime evidence for 1 mfa policy(ies), 0 session policy rule(s), 0 provisioning event(s), and 0 user(s) with role assignments") {
		t.Errorf("stdout = %q, want it to mention the ingested okta runtime evidence counts", stdout.String())
	}

	nodesRaw, err := os.ReadFile(filepath.Join(out, "ir", "nodes.jsonl"))
	if err != nil {
		t.Fatalf("read nodes.jsonl: %v", err)
	}
	if !strings.Contains(string(nodesRaw), "runtime-evidence-policy") {
		t.Errorf("nodes.jsonl does not mention runtime-evidence-policy; okta --runtime evidence was not merged into the graph")
	}
}

// TestCompileRuntimeOktaMissingFileFailsLoudly confirms that a
// --runtime directory with okta_mfa.json present but one of the other
// three okta_*.json artifacts missing is a real, loud error - the same
// "never silently treated as nothing collected" property
// TestCompileRuntimeMissingFileFailsLoudly already establishes for AWS -
// as opposed to okta_mfa.json being absent entirely, which is the
// expected, silent "Okta collection didn't run" case
// TestCompileIngestsRuntimeEvidence's runtimeDir (no Okta files at all)
// already exercises without error.
func TestCompileRuntimeOktaMissingFileFailsLoudly(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "runtime")
	s3Graph := &awscollectors.S3Graph{}
	iamGraph := &awscollectors.IAMGraph{}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{}
	securityGroupsGraph := &awscollectors.SecurityGroupsGraph{}
	if _, err := writeCollectOutput(runtimeDir, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, nil); err != nil {
		t.Fatalf("writeCollectOutput: %v", err)
	}
	// Hand-write only okta_mfa.json, simulating a partially-corrupt
	// runtime directory - writeCollectOutput itself never produces this
	// shape (it writes all four or none), so this has to be constructed
	// directly.
	if err := os.WriteFile(filepath.Join(runtimeDir, oktaMFAArtifactName), []byte(`{"policies":[]}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", oktaMFAArtifactName, err)
	}

	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out, "--runtime", runtimeDir}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), oktaSessionPolicyArtifactName) {
		t.Errorf("stderr = %q, want it to name the missing file", stderr.String())
	}
}

// TestCompileOmitsRuntimeEvidenceByDefault confirms that not passing
// --runtime - compile's default, unchanged behavior - produces no AWS
// nodes in the evidence graph at all, even though the minimal fixture's
// own static frontends produce plenty of other nodes.
func TestCompileOmitsRuntimeEvidenceByDefault(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runCompile exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "ingested runtime evidence") {
		t.Errorf("stdout = %q, want no mention of runtime evidence when --runtime is omitted", stdout.String())
	}
	nodesRaw, err := os.ReadFile(filepath.Join(out, "ir", "nodes.jsonl"))
	if err != nil {
		t.Fatalf("read nodes.jsonl: %v", err)
	}
	// Match the node ID prefix specifically ("id":"aws:...), not a bare
	// "aws:" substring - the minimal fixture's own Terraform data
	// legitimately contains the unrelated string "aws:kms" as an
	// sse_algorithm attribute value, which a looser substring check
	// would false-positive on.
	if strings.Contains(string(nodesRaw), `"id":"aws:`) {
		t.Errorf("nodes.jsonl contains an aws: node with no --runtime given")
	}
}

// TestCompileRuntimeMissingFileFailsLoudly confirms a --runtime
// directory that exists but is missing one of collect's two artifacts
// is a real, loud error - never silently treated as "nothing collected."
func TestCompileRuntimeMissingFileFailsLoudly(t *testing.T) {
	runtimeDir := t.TempDir() // exists, but empty - no aws_s3.json/aws_iam.json
	out := filepath.Join(t.TempDir(), "out")
	var stdout, stderr bytes.Buffer
	code := runCompile([]string{"--source", "../../testdata/fixtures/minimal", "--out", out, "--runtime", runtimeDir}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), awsS3ArtifactName) {
		t.Errorf("stderr = %q, want it to name the missing file", stderr.String())
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
