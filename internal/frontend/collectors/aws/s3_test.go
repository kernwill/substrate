package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// fakeS3 implements S3API by serving canned data loaded from this
// package's testdata fixtures (FR-3.10) instead of calling AWS. A bucket
// name absent from encryptionFixtures/pabFixtures/loggingFixtures
// simulates that call erroring for that bucket - the same "unresolved,
// not guessed" outcome CollectS3's own per-field collectors produce for
// a real API error.
type fakeS3 struct {
	bucketNames      []string
	encryptionByName map[string]struct{ Algorithm string }
	pabByName        map[string]struct {
		BlockPublicACLs, BlockPublicPolicy, IgnorePublicACLs, RestrictPublicBuckets bool
	}
	loggingByName map[string]struct {
		Enabled      bool
		TargetBucket string
	}
}

func loadFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	readJSON := func(name string, v any) { readTestdataJSON(t, name, v) }

	f := &fakeS3{}
	readJSON("buckets.json", &f.bucketNames)

	var encRaw map[string]struct {
		Algorithm string `json:"algorithm"`
	}
	readJSON("encryption.json", &encRaw)
	f.encryptionByName = make(map[string]struct{ Algorithm string }, len(encRaw))
	for k, v := range encRaw {
		f.encryptionByName[k] = struct{ Algorithm string }{v.Algorithm}
	}

	var pabRaw map[string]struct {
		BlockPublicACLs       bool `json:"block_public_acls"`
		BlockPublicPolicy     bool `json:"block_public_policy"`
		IgnorePublicACLs      bool `json:"ignore_public_acls"`
		RestrictPublicBuckets bool `json:"restrict_public_buckets"`
	}
	readJSON("public_access_block.json", &pabRaw)
	f.pabByName = make(map[string]struct {
		BlockPublicACLs, BlockPublicPolicy, IgnorePublicACLs, RestrictPublicBuckets bool
	}, len(pabRaw))
	for k, v := range pabRaw {
		f.pabByName[k] = struct {
			BlockPublicACLs, BlockPublicPolicy, IgnorePublicACLs, RestrictPublicBuckets bool
		}{v.BlockPublicACLs, v.BlockPublicPolicy, v.IgnorePublicACLs, v.RestrictPublicBuckets}
	}

	var logRaw map[string]struct {
		Enabled      bool   `json:"enabled"`
		TargetBucket string `json:"target_bucket"`
	}
	readJSON("logging.json", &logRaw)
	f.loggingByName = make(map[string]struct {
		Enabled      bool
		TargetBucket string
	}, len(logRaw))
	for k, v := range logRaw {
		f.loggingByName[k] = struct {
			Enabled      bool
			TargetBucket string
		}{v.Enabled, v.TargetBucket}
	}

	return f
}

func (f *fakeS3) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	out := &s3.ListBucketsOutput{}
	for _, name := range f.bucketNames {
		n := name
		out.Buckets = append(out.Buckets, types.Bucket{Name: &n})
	}
	return out, nil
}

func (f *fakeS3) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	enc, ok := f.encryptionByName[*params.Bucket]
	if !ok {
		return nil, errors.New("ServerSideEncryptionConfigurationNotFoundError")
	}
	return &s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: []types.ServerSideEncryptionRule{
				{ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
					SSEAlgorithm: types.ServerSideEncryption(enc.Algorithm),
				}},
			},
		},
	}, nil
}

func (f *fakeS3) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	pab, ok := f.pabByName[*params.Bucket]
	if !ok {
		return nil, errors.New("NoSuchPublicAccessBlockConfiguration")
	}
	return &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       &pab.BlockPublicACLs,
			BlockPublicPolicy:     &pab.BlockPublicPolicy,
			IgnorePublicAcls:      &pab.IgnorePublicACLs,
			RestrictPublicBuckets: &pab.RestrictPublicBuckets,
		},
	}, nil
}

func (f *fakeS3) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	log, ok := f.loggingByName[*params.Bucket]
	if !ok {
		return nil, errors.New("simulated API error")
	}
	if !log.Enabled {
		return &s3.GetBucketLoggingOutput{}, nil
	}
	target := log.TargetBucket
	return &s3.GetBucketLoggingOutput{
		LoggingEnabled: &types.LoggingEnabled{TargetBucket: &target},
	}, nil
}

var testObservedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestCollectS3(t *testing.T) {
	client := loadFakeS3(t)
	graph, err := CollectS3(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectS3: %v", err)
	}
	if len(graph.Buckets) != 4 {
		t.Fatalf("got %d buckets, want 4", len(graph.Buckets))
	}

	byName := make(map[string]Bucket, len(graph.Buckets))
	for _, b := range graph.Buckets {
		byName[b.Name] = b
	}

	alpha := byName["alpha"]
	if alpha.Encryption == nil || alpha.Encryption.Algorithm != "aws:kms" {
		t.Errorf("alpha.Encryption = %+v, want algorithm aws:kms", alpha.Encryption)
	}
	if alpha.PublicAccessBlock == nil || !alpha.PublicAccessBlock.BlockPublicACLs || !alpha.PublicAccessBlock.RestrictPublicBuckets {
		t.Errorf("alpha.PublicAccessBlock = %+v, want all four flags true", alpha.PublicAccessBlock)
	}
	if alpha.Logging == nil || !alpha.Logging.Enabled || alpha.Logging.TargetBucket != "alpha-logs" {
		t.Errorf("alpha.Logging = %+v, want enabled with target alpha-logs", alpha.Logging)
	}
	if alpha.Encryption.Provenance.Basis != "observed" || alpha.Encryption.Provenance.Timestamp != testObservedAt {
		t.Errorf("alpha.Encryption.Provenance = %+v, want Basis=observed, Timestamp=%v", alpha.Encryption.Provenance, testObservedAt)
	}

	beta := byName["beta"]
	if beta.Encryption == nil || beta.Encryption.Algorithm != "AES256" {
		t.Errorf("beta.Encryption = %+v, want algorithm AES256", beta.Encryption)
	}
	if beta.PublicAccessBlock == nil || beta.PublicAccessBlock.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("beta.PublicAccessBlock = %+v, want an Unresolved fact (no bucket-level config; account-level PAB is unknown, never guessed)", beta.PublicAccessBlock)
	}
	if beta.PublicAccessBlock != nil && beta.PublicAccessBlock.Provenance.UnresolvedReason == "" {
		t.Error("beta.PublicAccessBlock.Provenance.UnresolvedReason is empty, want the API error recorded")
	}
	if beta.Logging == nil || beta.Logging.Provenance.Confidence != provenance.Deterministic || beta.Logging.Enabled {
		t.Errorf("beta.Logging = %+v, want a resolved, disabled fact", beta.Logging)
	}

	gamma := byName["gamma"]
	if gamma.Logging == nil || gamma.Logging.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("gamma.Logging = %+v, want an Unresolved fact (simulated API error)", gamma.Logging)
	}

	delta := byName["delta"]
	if delta.Encryption == nil || delta.Encryption.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("delta.Encryption = %+v, want an Unresolved fact, not nil", delta.Encryption)
	}
	if delta.PublicAccessBlock == nil || delta.PublicAccessBlock.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("delta.PublicAccessBlock = %+v, want an Unresolved fact, not nil", delta.PublicAccessBlock)
	}
	if delta.Logging == nil || delta.Logging.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("delta.Logging = %+v, want an Unresolved fact, not nil", delta.Logging)
	}
}

// TestCollectS3EveryFieldNonNil confirms CollectS3 never leaves
// Encryption, PublicAccessBlock, or Logging as a nil pointer, even when
// every underlying API call fails - the fix for the bug where an
// unresolved field was indistinguishable from a bucket that was never
// queried at all.
func TestCollectS3EveryFieldNonNil(t *testing.T) {
	client := loadFakeS3(t)
	graph, err := CollectS3(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectS3: %v", err)
	}
	for _, b := range graph.Buckets {
		if b.Encryption == nil {
			t.Errorf("%s.Encryption is nil, want a non-nil fact (resolved or Unresolved)", b.Name)
		}
		if b.PublicAccessBlock == nil {
			t.Errorf("%s.PublicAccessBlock is nil, want a non-nil fact (resolved or Unresolved)", b.Name)
		}
		if b.Logging == nil {
			t.Errorf("%s.Logging is nil, want a non-nil fact (resolved or Unresolved)", b.Name)
		}
	}
}

// TestCollectS3BucketsSortedByName confirms CollectS3's own output order
// doesn't depend on ListBuckets' response order, which the SDK does not
// document as stable.
func TestCollectS3BucketsSortedByName(t *testing.T) {
	client := loadFakeS3(t)
	graph, err := CollectS3(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectS3: %v", err)
	}
	for i := 1; i < len(graph.Buckets); i++ {
		if graph.Buckets[i-1].Name >= graph.Buckets[i].Name {
			t.Fatalf("buckets not sorted: %q >= %q", graph.Buckets[i-1].Name, graph.Buckets[i].Name)
		}
	}
}
