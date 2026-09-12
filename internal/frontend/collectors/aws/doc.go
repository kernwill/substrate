// Package aws collects live AWS account state (FR-3: runtime collection,
// "the evidence-of-effectiveness half," IVV-CSO-SEE) - the Observed
// counterpart to internal/frontend's static, Declared parsers.
//
// # Credentials
//
// Every collector in this package takes an already-constructed API
// client, never credentials or a region string itself. Production
// callers build that client from the AWS SDK's standard default
// credential chain (aws-sdk-go-v2's config.LoadDefaultConfig) against
// whatever read-only IAM role or user the customer has provisioned - see
// docs/aws-readonly-policy.json for the exact, minimal permission set
// this package's collectors need, and FR-3.7's "operate under a
// strictly read-only IAM role; publish that policy document." This
// package never constructs, assumes, or refreshes credentials on its
// own; that is entirely the caller's (and ultimately the customer's)
// responsibility.
//
// # GovCloud (FR-3.8)
//
// No GovCloud-specific logic exists in this package, deliberately: every
// API call here (S3's ListBuckets/GetBucketEncryption/
// GetPublicAccessBlock/GetBucketLogging) is a standard, partition-generic
// operation the AWS SDK already resolves correctly against a GovCloud
// region (e.g. us-gov-west-1) once the caller's client is configured for
// that region - there is nothing about "which partition" for these
// specific calls to special-case. That may stop being true the moment a
// future collector here needs to construct or parse an ARN, since
// GovCloud ARNs use the "aws-us-gov" partition segment instead of "aws" -
// worth remembering before assuming this package is GovCloud-safe by
// default rather than by inspection.
//
// # Testing (FR-3.10)
//
// Every collector is defined against a narrow, hand-written Go interface
// naming only the specific SDK operations it calls (e.g. S3API for the S3
// collector), never the SDK's full client type. The real *s3.Client
// satisfies that interface structurally, with no adapter code; tests
// substitute a fake implementation that serves canned responses loaded
// from this package's testdata fixtures. No collector or its tests ever
// makes a live AWS call - "no live cloud dependency in unit tests" is
// enforced by the interface boundary itself, not by convention.
//
// See docs/adr/0008 for the full reasoning behind this shape.
package aws
