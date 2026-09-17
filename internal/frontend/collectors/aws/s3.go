package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kernwill/substrate/internal/provenance"
)

// S3CollectorVersion is this file's own collector version (FR-4.1),
// bumped whenever a change here could produce different facts from the
// same account state. It is independent of the overall substrate binary
// version and of any other collector in this package.
const S3CollectorVersion = "aws-s3/v0.1.0"

// S3API names only the S3 operations this file's collector calls,
// deliberately narrower than the full *s3.Client the AWS SDK generates -
// see this package's doc.go for why (FR-3.10's fixture-based testing).
// *s3.Client satisfies this interface with no adapter code, since Go
// interface satisfaction is structural.
type S3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
}

// Bucket is one collected S3 bucket. Encryption, PublicAccessBlock, and
// Logging are never nil - CollectS3 always attempts all three calls and
// always records a fact, resolved or not. Check each field's own
// Provenance.Confidence: Deterministic means the value was actually
// read; Unresolved means the API call failed or returned something this
// collector could not interpret, with Provenance.UnresolvedReason saying
// why (provenance.Record's own "never leave undetermined unexplained"
// requirement, which Validate enforces). An earlier version of this file
// returned a nil pointer for an unresolved field instead, which made a
// permissions error or a throttled call byte-identical to a bucket that
// was never queried at all - exactly the "fail silent" outcome
// CLAUDE.md's "absence of evidence is not evidence of compliance" exists
// to rule out.
type Bucket struct {
	Name              string
	Encryption        *BucketEncryption
	PublicAccessBlock *BucketPublicAccessBlock
	Logging           *BucketLogging
}

// BucketEncryption is one bucket's default server-side encryption
// algorithm (the same measurement Terraform's
// aws_s3_bucket_server_side_encryption_configuration mapping records for
// Declared evidence - see internal/frontend/terraform/ir.go's
// mapEncryption). Only the first configuration rule's algorithm is
// recorded, matching that mapper's own scope. Algorithm is meaningful
// only when Provenance.Confidence is Deterministic.
type BucketEncryption struct {
	Algorithm  string
	Provenance provenance.Record
}

// BucketPublicAccessBlock is one bucket's four Block Public Access
// flags - the Observed counterpart to Terraform's
// aws_s3_bucket_public_access_block mapping (mapPublicAccessBlock). The
// four flags are meaningful only when Provenance.Confidence is
// Deterministic.
type BucketPublicAccessBlock struct {
	BlockPublicACLs       bool
	BlockPublicPolicy     bool
	IgnorePublicACLs      bool
	RestrictPublicBuckets bool
	Provenance            provenance.Record
}

// BucketLogging is whether server access logging is enabled for a
// bucket, and where to if so. Enabled and TargetBucket are meaningful
// only when Provenance.Confidence is Deterministic.
type BucketLogging struct {
	Enabled      bool
	TargetBucket string
	Provenance   provenance.Record
}

// S3Graph is every bucket this collector found in one account/region
// pass, per FR-3.5.
type S3Graph struct {
	Buckets []Bucket
}

// CollectS3 lists every bucket visible to client and reads its
// encryption, Block Public Access, and access-logging configuration, up
// to maxConcurrentItems at a time (collectConcurrent, concurrent.go).
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// "when the fact was true at the source... an API response's observation
// time" (provenance.Record.Timestamp's own doc comment). This package
// never calls time.Now() itself; production callers pass
// time.Now().UTC(), and tests pass a fixed value, so this file's own
// logic carries no wall-clock dependency even though the facts it
// produces are inherently tied to when the account was actually queried
// (unlike a Declared fact's git-commit timestamp, an Observed fact has
// no earlier "true at the source" moment to recover - the observation
// itself is the event).
func CollectS3(ctx context.Context, client S3API, observedAt time.Time) (*S3Graph, error) {
	names, err := listBucketNames(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: s3: list buckets: %w", err)
	}
	buckets, err := collectConcurrent(ctx, names, func(ctx context.Context, name string) Bucket {
		return Bucket{
			Name:              name,
			Encryption:        collectBucketEncryption(ctx, client, name, observedAt),
			PublicAccessBlock: collectBucketPublicAccessBlock(ctx, client, name, observedAt),
			Logging:           collectBucketLogging(ctx, client, name, observedAt),
		}
	})
	if err != nil {
		return nil, fmt.Errorf("aws: s3: collect buckets: %w", err)
	}
	return &S3Graph{Buckets: buckets}, nil
}

// listBucketNames pages through every bucket in the account, sorted so
// CollectS3's own output order doesn't depend on the API's response
// order (which ListBuckets does not document as stable) - the same
// reproducibility discipline internal/frontend's static parsers already
// apply to filesystem directory-listing order. Sorting here also gives
// CollectS3's per-index goroutine assignment (buckets[i] = ...) a
// deterministic mapping from bucket name to output slot, independent of
// the bounded worker pool's scheduling order.
func listBucketNames(ctx context.Context, client S3API) ([]string, error) {
	paginator := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{})
	var names []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, b := range page.Buckets {
			if b.Name == nil {
				continue
			}
			names = append(names, *b.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// s3Record and s3UnresolvedRecord are thin wrappers around this
// package's shared observedRecord/unresolvedRecord (provenance.go),
// fixing SourceType's "aws" and the "bucket" parameter key so each call
// site below only names what's actually specific to it.
func s3Record(bucket, api string, observedAt time.Time) provenance.Record {
	return observedRecord(S3CollectorVersion, api, map[string]string{"bucket": bucket}, observedAt)
}

func s3UnresolvedRecord(bucket, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(S3CollectorVersion, api, reason, map[string]string{"bucket": bucket}, observedAt)
}

// collectBucketEncryption reads bucket's default encryption
// configuration. Every bucket has had one since AWS made SSE-S3 the
// account-wide default in January 2023, so an error here is treated as
// genuinely unresolved rather than "not encrypted" - a bucket predating
// that change on an old account, a permissions error, and a transient
// fault all produce the same API error shape, and guessing which one
// occurred would be exactly the kind of guess FR-2.3/FR-3 forbid.
func collectBucketEncryption(ctx context.Context, client S3API, bucket string, observedAt time.Time) *BucketEncryption {
	const api = "s3:GetBucketEncryption"
	out, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: &bucket})
	if err != nil {
		return &BucketEncryption{Provenance: s3UnresolvedRecord(bucket, api, err.Error(), observedAt)}
	}
	if out.ServerSideEncryptionConfiguration == nil || len(out.ServerSideEncryptionConfiguration.Rules) == 0 {
		return &BucketEncryption{Provenance: s3UnresolvedRecord(bucket, api, "response had no encryption configuration rules", observedAt)}
	}
	rule := out.ServerSideEncryptionConfiguration.Rules[0]
	if rule.ApplyServerSideEncryptionByDefault == nil {
		return &BucketEncryption{Provenance: s3UnresolvedRecord(bucket, api, "response rule had no default encryption applied", observedAt)}
	}
	return &BucketEncryption{
		Algorithm:  string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm),
		Provenance: s3Record(bucket, api, observedAt),
	}
}

// collectBucketPublicAccessBlock reads bucket's bucket-level Block
// Public Access configuration.
//
// A bucket with no bucket-level configuration at all makes
// GetPublicAccessBlock return a NoSuchPublicAccessBlockConfiguration
// error - and that is deliberately NOT treated as "public access block is
// off" here. S3's own documentation is explicit that the *effective*
// posture is the most restrictive combination of the bucket-level
// setting and a separate, account-level Block Public Access setting
// (queried via a different API, s3control:GetPublicAccessBlock, which
// this collector does not call yet): a bucket with no bucket-level
// config can still be fully locked down by the account-level one. Since
// this collector cannot see that account-level setting, it genuinely
// does not know the effective posture on a NotFound-shaped error, and
// records Unresolved rather than asserting all-flags-false as if that
// were the whole truth - the same "never guess" discipline FR-2.3
// established for static parsing, applied here to a live-API nuance
// discovered while building this collector, not a documented AWS
// behavior every future maintainer would otherwise think to check for.
func collectBucketPublicAccessBlock(ctx context.Context, client S3API, bucket string, observedAt time.Time) *BucketPublicAccessBlock {
	const api = "s3:GetPublicAccessBlock"
	out, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket})
	if err != nil {
		return &BucketPublicAccessBlock{Provenance: s3UnresolvedRecord(bucket, api, err.Error(), observedAt)}
	}
	cfg := out.PublicAccessBlockConfiguration
	if cfg == nil || cfg.BlockPublicAcls == nil || cfg.BlockPublicPolicy == nil || cfg.IgnorePublicAcls == nil || cfg.RestrictPublicBuckets == nil {
		return &BucketPublicAccessBlock{Provenance: s3UnresolvedRecord(bucket, api, "response had no complete public access block configuration", observedAt)}
	}
	return &BucketPublicAccessBlock{
		BlockPublicACLs:       *cfg.BlockPublicAcls,
		BlockPublicPolicy:     *cfg.BlockPublicPolicy,
		IgnorePublicACLs:      *cfg.IgnorePublicAcls,
		RestrictPublicBuckets: *cfg.RestrictPublicBuckets,
		Provenance:            s3Record(bucket, api, observedAt),
	}
}

// collectBucketLogging reads whether server access logging is enabled
// for bucket. Unlike encryption and public access block,
// GetBucketLogging does not error when logging is off - it returns a
// response with a nil LoggingEnabled - so there is no ambiguous
// not-found case to reason about here: a real API error is the only
// unresolved case.
func collectBucketLogging(ctx context.Context, client S3API, bucket string, observedAt time.Time) *BucketLogging {
	const api = "s3:GetBucketLogging"
	out, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &bucket})
	if err != nil {
		return &BucketLogging{Provenance: s3UnresolvedRecord(bucket, api, err.Error(), observedAt)}
	}
	if out.LoggingEnabled == nil {
		return &BucketLogging{
			Enabled:    false,
			Provenance: s3Record(bucket, api, observedAt),
		}
	}
	target := ""
	if out.LoggingEnabled.TargetBucket != nil {
		target = *out.LoggingEnabled.TargetBucket
	}
	return &BucketLogging{
		Enabled:      true,
		TargetBucket: target,
		Provenance:   s3Record(bucket, api, observedAt),
	}
}
