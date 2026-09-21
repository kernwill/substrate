package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awscollectors "github.com/kernwill/substrate/internal/frontend/collectors/aws"
	oktacollectors "github.com/kernwill/substrate/internal/frontend/collectors/okta"
)

// TestWriteCollectOutput exercises the real logic in this command
// (writing and atomically publishing collect's artifacts) against
// synthetic graphs, with no AWS credentials or client involved -
// CollectS3, CollectIAM, CollectCloudTrail, and CollectSecurityGroups
// already have their own thorough, fixture-backed tests in
// internal/frontend/collectors/aws.
func TestWriteCollectOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	s3Graph := &awscollectors.S3Graph{Buckets: []awscollectors.Bucket{{Name: "example-bucket"}}}
	iamGraph := &awscollectors.IAMGraph{Users: []awscollectors.IAMUser{{Name: "example-user"}}}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{Trails: []awscollectors.Trail{{Name: "example-trail"}}}
	securityGroupsGraph := &awscollectors.SecurityGroupsGraph{Rules: []awscollectors.SecurityGroupRule{{SecurityGroupID: "sg-example"}}}

	warning, err := writeCollectOutput(out, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, nil)
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

	raw, err = os.ReadFile(filepath.Join(out, awsSecurityGroupsArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsSecurityGroupsArtifactName, err)
	}
	var gotSecurityGroups awscollectors.SecurityGroupsGraph
	if err := json.Unmarshal(raw, &gotSecurityGroups); err != nil {
		t.Fatalf("parse %s: %v", awsSecurityGroupsArtifactName, err)
	}
	if len(gotSecurityGroups.Rules) != 1 || gotSecurityGroups.Rules[0].SecurityGroupID != "sg-example" {
		t.Errorf("%s contents = %+v, want one rule for sg-example", awsSecurityGroupsArtifactName, gotSecurityGroups)
	}

	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("out+\".tmp\" = %v, want it gone after a successful write", err)
	}

	for _, name := range []string{oktaMFAArtifactName, oktaSessionPolicyArtifactName, oktaProvisioningArtifactName, oktaAdminRoleArtifactName} {
		if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
			t.Errorf("%s exists, want it absent when okta is nil (Okta collection not configured)", name)
		}
	}
}

// TestWriteCollectOutputWithOkta mirrors TestWriteCollectOutput for the
// case where Okta collection ran (okta non-nil): all four of its own
// artifact files must be written alongside the three AWS ones.
func TestWriteCollectOutputWithOkta(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	s3Graph := &awscollectors.S3Graph{}
	iamGraph := &awscollectors.IAMGraph{}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{}
	securityGroupsGraph := &awscollectors.SecurityGroupsGraph{}
	okta := &oktaResults{
		MFA:           &oktacollectors.MFAEnrollmentGraph{Policies: []oktacollectors.MFAEnrollmentPolicy{{ID: "policy-1"}}},
		SessionPolicy: &oktacollectors.SessionPolicyGraph{Rules: []oktacollectors.SessionPolicyRule{{PolicyID: "sp-1", RuleID: "rule-1"}}},
		Provisioning:  &oktacollectors.ProvisioningEventGraph{Events: []oktacollectors.ProvisioningEvent{{ID: "evt-1"}}},
		AdminRole:     &oktacollectors.AdminRoleAssignmentGraph{Users: []oktacollectors.AdminRoleAssignment{{UserID: "user-1"}}},
	}

	if _, err := writeCollectOutput(out, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, okta); err != nil {
		t.Fatalf("writeCollectOutput: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(out, oktaMFAArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", oktaMFAArtifactName, err)
	}
	var gotMFA oktacollectors.MFAEnrollmentGraph
	if err := json.Unmarshal(raw, &gotMFA); err != nil {
		t.Fatalf("parse %s: %v", oktaMFAArtifactName, err)
	}
	if len(gotMFA.Policies) != 1 || gotMFA.Policies[0].ID != "policy-1" {
		t.Errorf("%s contents = %+v, want one policy named policy-1", oktaMFAArtifactName, gotMFA)
	}

	for _, name := range []string{oktaSessionPolicyArtifactName, oktaProvisioningArtifactName, oktaAdminRoleArtifactName} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("stat %s: %v, want it present when okta is non-nil", name, err)
		}
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
	emptySecurityGroups := &awscollectors.SecurityGroupsGraph{}

	if _, err := writeCollectOutput(out, empty, emptyIAM, emptyCloudTrail, emptySecurityGroups, nil); err != nil {
		t.Fatalf("first writeCollectOutput: %v", err)
	}
	if _, err := writeCollectOutput(out, empty, emptyIAM, emptyCloudTrail, emptySecurityGroups, nil); err != nil {
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

// TestRunCollectRequiresOktaClientIDAndPrivateKeyWithOrgURL confirms a
// partially-configured Okta org (--okta-org-url with no client ID or
// private key) fails loudly before ever reaching config.LoadDefaultConfig,
// the same "flag validation happens first" property
// TestRunCollectRequiresOut relies on for AWS. Asserts on the specific
// validation message, not just exit code 2 - a bare exit-code check
// here would also pass if this validation were deleted entirely, since
// loadOktaPrivateKey("") fails downstream with its own exit-2 error
// (confirmed while writing this test: removing the validation left this
// assertion's exit-code-only version green for the wrong reason).
func TestRunCollectRequiresOktaClientIDAndPrivateKeyWithOrgURL(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCollect([]string{"--out", filepath.Join(t.TempDir(), "out"), "--okta-org-url", "https://example.okta.com"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("exit code = %d, want 2; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--okta-org-url requires --okta-client-id and --okta-private-key") {
		t.Errorf("stderr = %q, want it to name the specific missing-flag validation", stderr.String())
	}
}

// TestLoadOktaPrivateKey covers both key encodings loadOktaPrivateKey
// must accept - see its own doc comment for why both are tried rather
// than assuming one.
func TestLoadOktaPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	t.Run("PKCS1", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		got, err := loadOktaPrivateKey(path)
		if err != nil {
			t.Fatalf("loadOktaPrivateKey: %v", err)
		}
		if got.N.Cmp(key.N) != 0 {
			t.Error("loaded key does not match the original PKCS1-encoded key")
		}
	})

	t.Run("PKCS8", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal PKCS8: %v", err)
		}
		block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		got, err := loadOktaPrivateKey(path)
		if err != nil {
			t.Fatalf("loadOktaPrivateKey: %v", err)
		}
		if got.N.Cmp(key.N) != 0 {
			t.Error("loaded key does not match the original PKCS8-encoded key")
		}
	})

	t.Run("not PEM", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		if _, err := loadOktaPrivateKey(path); err == nil {
			t.Error("loadOktaPrivateKey succeeded on a non-PEM file, want an error")
		}
	})
}
