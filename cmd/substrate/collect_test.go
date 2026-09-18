package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
)

// TestWriteCollectOutput exercises the real logic in this command
// (writing and atomically publishing collect's three artifacts) against
// synthetic graphs, with no AWS credentials or client involved -
// CollectS3, CollectIAM, and CollectCloudTrail already have their own
// thorough, fixture-backed tests in internal/frontend/collectors/aws.
func TestWriteCollectOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	s3Graph := &awscollectors.S3Graph{Buckets: []awscollectors.Bucket{{Name: "example-bucket"}}}
	iamGraph := &awscollectors.IAMGraph{Users: []awscollectors.IAMUser{{Name: "example-user"}}}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{Trails: []awscollectors.Trail{{Name: "example-trail"}}}

	warning, err := writeCollectOutput(out, s3Graph, iamGraph, cloudTrailGraph)
	if err != nil {
		t.Fatalf("writeCollectOutput: %v", err)
	}
	if warning != "" {
		t.Errorf("warning = %q, want empty on a first, successful write", warning)
	}

	raw, err := os.ReadFile(filepath.Join(out, awsS3ArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsS3ArtifactName, err)
	}
	var gotS3 awscollectors.S3Graph
	if err := json.Unmarshal(raw, &gotS3); err != nil {
		t.Fatalf("parse %s: %v", awsS3ArtifactName, err)
	}
	if len(gotS3.Buckets) != 1 || gotS3.Buckets[0].Name != "example-bucket" {
		t.Errorf("%s contents = %+v, want one bucket named example-bucket", awsS3ArtifactName, gotS3)
	}

	raw, err = os.ReadFile(filepath.Join(out, awsIAMArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsIAMArtifactName, err)
	}
	var gotIAM awscollectors.IAMGraph
	if err := json.Unmarshal(raw, &gotIAM); err != nil {
		t.Fatalf("parse %s: %v", awsIAMArtifactName, err)
	}
	if len(gotIAM.Users) != 1 || gotIAM.Users[0].Name != "example-user" {
		t.Errorf("%s contents = %+v, want one user named example-user", awsIAMArtifactName, gotIAM)
	}

	raw, err = os.ReadFile(filepath.Join(out, awsCloudTrailArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsCloudTrailArtifactName, err)
	}
	var gotCloudTrail awscollectors.CloudTrailGraph
	if err := json.Unmarshal(raw, &gotCloudTrail); err != nil {
		t.Fatalf("parse %s: %v", awsCloudTrailArtifactName, err)
	}
	if len(gotCloudTrail.Trails) != 1 || gotCloudTrail.Trails[0].Name != "example-trail" {
		t.Errorf("%s contents = %+v, want one trail named example-trail", awsCloudTrailArtifactName, gotCloudTrail)
	}

	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("out+\".tmp\" = %v, want it gone after a successful write", err)
	}
}

// TestWriteCollectOutputRerunLeavesNoBackupDirectory mirrors
// TestCompileRerunLeavesNoBackupDirectory (compile_test.go): a second
// write to the same --out must clean up its backup on success.
func TestWriteCollectOutputRerunLeavesNoBackupDirectory(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	empty := &awscollectors.S3Graph{}
	emptyIAM := &awscollectors.IAMGraph{}
	emptyCloudTrail := &awscollectors.CloudTrailGraph{}

	if _, err := writeCollectOutput(out, empty, emptyIAM, emptyCloudTrail); err != nil {
		t.Fatalf("first writeCollectOutput: %v", err)
	}
	if _, err := writeCollectOutput(out, empty, emptyIAM, emptyCloudTrail); err != nil {
		t.Fatalf("second writeCollectOutput: %v", err)
	}

	if _, err := os.Stat(out + ".old"); !os.IsNotExist(err) {
		t.Errorf("out+\".old\" = %v, want it gone after a successful rerun", err)
	}
}

// TestRunCollectRequiresOut confirms runCollect fails loudly (exit 2)
// rather than attempting live AWS calls when --out is missing - this is
// the one path in this file testable without an AWS client, since flag
// validation happens before config.LoadDefaultConfig is ever called.
func TestRunCollectRequiresOut(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCollect(nil, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2; stderr: %s", code, stderr.String())
	}
}
