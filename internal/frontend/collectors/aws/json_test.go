package aws

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kernwill/substrate/internal/provenance"
)

// TestS3GraphJSONRoundTrip and TestIAMGraphJSONRoundTrip guard the JSON
// tags s3.go and iam.go carry: substrate collect writes these types to
// disk (<out>/aws_s3.json, <out>/aws_iam.json), and substrate compile
// reads them back in via --runtime - so a lossy round trip here would
// silently drop or corrupt Observed evidence between those two commands,
// with no test anywhere else positioned to catch it (every existing
// test in this package asserts on the Go structs directly, never on
// their serialized form).
func TestS3GraphJSONRoundTrip(t *testing.T) {
	want := S3Graph{Buckets: []Bucket{
		{
			Name: "alpha",
			Encryption: &BucketEncryption{
				Algorithm:  "aws:kms",
				Provenance: testProvenanceRecord(),
			},
			PublicAccessBlock: &BucketPublicAccessBlock{
				BlockPublicACLs:       true,
				BlockPublicPolicy:     true,
				IgnorePublicACLs:      true,
				RestrictPublicBuckets: true,
				Provenance:            testProvenanceRecord(),
			},
			Logging: &BucketLogging{
				Enabled:      true,
				TargetBucket: "alpha-logs",
				Provenance:   testProvenanceRecord(),
			},
		},
		{
			Name:              "beta",
			Encryption:        &BucketEncryption{Provenance: unresolvedProvenanceRecord()},
			PublicAccessBlock: &BucketPublicAccessBlock{Provenance: unresolvedProvenanceRecord()},
			Logging:           &BucketLogging{Provenance: unresolvedProvenanceRecord()},
		},
	}}

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got S3Graph
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Buckets) != len(want.Buckets) {
		t.Fatalf("got %d buckets, want %d", len(got.Buckets), len(want.Buckets))
	}
	// provenance.Record embeds a map (Locator.Parameters), so these
	// structs aren't comparable with == - DeepEqual instead.
	for i := range want.Buckets {
		if got.Buckets[i].Name != want.Buckets[i].Name {
			t.Errorf("bucket %d: Name = %q, want %q", i, got.Buckets[i].Name, want.Buckets[i].Name)
		}
		if !reflect.DeepEqual(*got.Buckets[i].Encryption, *want.Buckets[i].Encryption) {
			t.Errorf("bucket %d: Encryption = %+v, want %+v", i, got.Buckets[i].Encryption, want.Buckets[i].Encryption)
		}
		if !reflect.DeepEqual(*got.Buckets[i].PublicAccessBlock, *want.Buckets[i].PublicAccessBlock) {
			t.Errorf("bucket %d: PublicAccessBlock = %+v, want %+v", i, got.Buckets[i].PublicAccessBlock, want.Buckets[i].PublicAccessBlock)
		}
		if !reflect.DeepEqual(*got.Buckets[i].Logging, *want.Buckets[i].Logging) {
			t.Errorf("bucket %d: Logging = %+v, want %+v", i, got.Buckets[i].Logging, want.Buckets[i].Logging)
		}
	}
}

func TestIAMGraphJSONRoundTrip(t *testing.T) {
	want := IAMGraph{Users: []IAMUser{
		{
			Name:            "alice",
			ConsolePassword: &ConsolePassword{Enabled: true, Provenance: testProvenanceRecord()},
			MFADevices:      &MFADevices{Count: 2, Provenance: testProvenanceRecord()},
			AccessKeys: &AccessKeys{
				Keys:       []AccessKey{{Active: true, AgeDays: 214}, {Active: false, AgeDays: 2192}},
				Provenance: testProvenanceRecord(),
			},
		},
		{
			Name:            "carol",
			ConsolePassword: &ConsolePassword{Enabled: false, Provenance: testProvenanceRecord()},
			MFADevices:      &MFADevices{Provenance: unresolvedProvenanceRecord()},
			AccessKeys:      &AccessKeys{Provenance: unresolvedProvenanceRecord()},
		},
	}}

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got IAMGraph
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.Users) != len(want.Users) {
		t.Fatalf("got %d users, want %d", len(got.Users), len(want.Users))
	}
	for i := range want.Users {
		if got.Users[i].Name != want.Users[i].Name {
			t.Errorf("user %d: Name = %q, want %q", i, got.Users[i].Name, want.Users[i].Name)
		}
		if !reflect.DeepEqual(*got.Users[i].ConsolePassword, *want.Users[i].ConsolePassword) {
			t.Errorf("user %d: ConsolePassword = %+v, want %+v", i, got.Users[i].ConsolePassword, want.Users[i].ConsolePassword)
		}
		if !reflect.DeepEqual(*got.Users[i].MFADevices, *want.Users[i].MFADevices) {
			t.Errorf("user %d: MFADevices = %+v, want %+v", i, got.Users[i].MFADevices, want.Users[i].MFADevices)
		}
		if !reflect.DeepEqual(*got.Users[i].AccessKeys, *want.Users[i].AccessKeys) {
			t.Errorf("user %d: AccessKeys = %+v, want %+v", i, got.Users[i].AccessKeys, want.Users[i].AccessKeys)
		}
	}
}

func testProvenanceRecord() provenance.Record {
	r := observedRecord("test/v0", "test:API", map[string]string{"k": "v"}, testObservedAt)
	return r
}

func unresolvedProvenanceRecord() provenance.Record {
	return unresolvedRecord("test/v0", "test:API", "simulated failure", map[string]string{"k": "v"}, testObservedAt)
}
