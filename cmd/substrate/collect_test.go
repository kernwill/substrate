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
// CollectS3, CollectIAM, CollectCloudTrail, CollectSecurityGroups,
// CollectSubnets, and CollectGuardDuty already have their own thorough,
// fixture-backed tests in internal/frontend/collectors/aws.
func TestWriteCollectOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	s3Graph := &awscollectors.S3Graph{Buckets: []awscollectors.Bucket{{Name: "example-bucket"}}}
	iamGraph := &awscollectors.IAMGraph{Users: []awscollectors.IAMUser{{Name: "example-user"}}}
	cloudTrailGraph := &awscollectors.CloudTrailGraph{Trails: []awscollectors.Trail{{Name: "example-trail"}}}
	securityGroupsGraph := &awscollectors.SecurityGroupsGraph{Rules: []awscollectors.SecurityGroupRule{{SecurityGroupID: "sg-example"}}}
	subnetsGraph := &awscollectors.SubnetsGraph{Subnets: []awscollectors.Subnet{{SubnetID: "subnet-example"}}}
	guardDutyGraph := &awscollectors.GuardDutyGraph{Detectors: []awscollectors.Detector{{Present: true, DetectorID: "detector-example"}}}
	configGraph := &awscollectors.ConfigGraph{Recorders: []awscollectors.ConfigRecorder{{Present: true, Name: "config-example"}}}
	securityHubGraph := &awscollectors.SecurityHubGraph{Hubs: []awscollectors.Hub{{Present: true, HubARN: "hub-example"}}}
	kmsGraph := &awscollectors.KMSGraph{Keys: []awscollectors.Key{{KeyID: "key-example"}}}

	warning, err := writeCollectOutput(out, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, subnetsGraph, guardDutyGraph, configGraph, securityHubGraph, kmsGraph, nil)
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

	raw, err = os.ReadFile(filepath.Join(out, awsSubnetsArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsSubnetsArtifactName, err)
	}
	var gotSubnets awscollectors.SubnetsGraph
	if err := json.Unmarshal(raw, &gotSubnets); err != nil {
		t.Fatalf("parse %s: %v", awsSubnetsArtifactName, err)
	}
	if len(gotSubnets.Subnets) != 1 || gotSubnets.Subnets[0].SubnetID != "subnet-example" {
		t.Errorf("%s contents = %+v, want one subnet named subnet-example", awsSubnetsArtifactName, gotSubnets)
	}

	raw, err = os.ReadFile(filepath.Join(out, awsGuardDutyArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsGuardDutyArtifactName, err)
	}
	var gotGuardDuty awscollectors.GuardDutyGraph
	if err := json.Unmarshal(raw, &gotGuardDuty); err != nil {
		t.Fatalf("parse %s: %v", awsGuardDutyArtifactName, err)
	}
	if len(gotGuardDuty.Detectors) != 1 || gotGuardDuty.Detectors[0].DetectorID != "detector-example" {
		t.Errorf("%s contents = %+v, want one detector named detector-example", awsGuardDutyArtifactName, gotGuardDuty)
	}

	raw, err = os.ReadFile(filepath.Join(out, awsConfigArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsConfigArtifactName, err)
	}
	var gotConfig awscollectors.ConfigGraph
	if err := json.Unmarshal(raw, &gotConfig); err != nil {
		t.Fatalf("parse %s: %v", awsConfigArtifactName, err)
	}
	if len(gotConfig.Recorders) != 1 || gotConfig.Recorders[0].Name != "config-example" {
		t.Errorf("%s contents = %+v, want one recorder named config-example", awsConfigArtifactName, gotConfig)
	}

	raw, err = os.ReadFile(filepath.Join(out, awsSecurityHubArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsSecurityHubArtifactName, err)
	}
	var gotSecurityHub awscollectors.SecurityHubGraph
	if err := json.Unmarshal(raw, &gotSecurityHub); err != nil {
		t.Fatalf("parse %s: %v", awsSecurityHubArtifactName, err)
	}
	if len(gotSecurityHub.Hubs) != 1 || gotSecurityHub.Hubs[0].HubARN != "hub-example" {
		t.Errorf("%s contents = %+v, want one hub named hub-example", awsSecurityHubArtifactName, gotSecurityHub)
	}

	raw, err = os.ReadFile(filepath.Join(out, awsKMSArtifactName))
	if err != nil {
		t.Fatalf("read %s: %v", awsKMSArtifactName, err)
	}
	var gotKMS awscollectors.KMSGraph
	if err := json.Unmarshal(raw, &gotKMS); err != nil {
		t.Fatalf("parse %s: %v", awsKMSArtifactName, err)
	}
	if len(gotKMS.Keys) != 1 || gotKMS.Keys[0].KeyID != "key-example" {
		t.Errorf("%s contents = %+v, want one key named key-example", awsKMSArtifactName, gotKMS)
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
	subnetsGraph := &awscollectors.SubnetsGraph{}
	guardDutyGraph := &awscollectors.GuardDutyGraph{}
	configGraph := &awscollectors.ConfigGraph{}
	securityHubGraph := &awscollectors.SecurityHubGraph{}
	kmsGraph := &awscollectors.KMSGraph{}
	okta := &oktaResults{
		MFA:           &oktacollectors.MFAEnrollmentGraph{Policies: []oktacollectors.MFAEnrollmentPolicy{{ID: "policy-1"}}},
		SessionPolicy: &oktacollectors.SessionPolicyGraph{Rules: []oktacollectors.SessionPolicyRule{{PolicyID: "sp-1", RuleID: "rule-1"}}},
		Provisioning:  &oktacollectors.ProvisioningEventGraph{Events: []oktacollectors.ProvisioningEvent{{ID: "evt-1"}}},
		AdminRole:     &oktacollectors.AdminRoleAssignmentGraph{Users: []oktacollectors.AdminRoleAssignment{{UserID: "user-1"}}},
	}

	if _, err := writeCollectOutput(out, s3Graph, iamGraph, cloudTrailGraph, securityGroupsGraph, subnetsGraph, guardDutyGraph, configGraph, securityHubGraph, kmsGraph, okta); err != nil {
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
	emptySubnets := &awscollectors.SubnetsGraph{}
	emptyGuardDuty := &awscollectors.GuardDutyGraph{}
	emptyConfig := &awscollectors.ConfigGraph{}
	emptySecurityHub := &awscollectors.SecurityHubGraph{}
	emptyKMS := &awscollectors.KMSGraph{}

	if _, err := writeCollectOutput(out, empty, emptyIAM, emptyCloudTrail, emptySecurityGroups, emptySubnets, emptyGuardDuty, emptyConfig, emptySecurityHub, emptyKMS, nil); err != nil {
		t.Fatalf("first writeCollectOutput: %v", err)
	}
	if _, err := writeCollectOutput(out, empty, emptyIAM, emptyCloudTrail, emptySecurityGroups, emptySubnets, emptyGuardDuty, emptyConfig, emptySecurityHub, emptyKMS, nil); err != nil {
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
