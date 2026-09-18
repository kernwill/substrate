package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/kernwill/substrate/internal/provenance"
)

// CloudTrailCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const CloudTrailCollectorVersion = "aws-cloudtrail/v0.1.0"

// CloudTrailAPI names only the CloudTrail operations this file's
// collector calls. See this package's doc.go for why this is a narrow,
// hand-written interface rather than the full *cloudtrail.Client
// (FR-3.10's fixture-based testing).
type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// Trail is one collected CloudTrail trail. Config and Logging are never
// nil - see Bucket's doc comment (s3.go) for why this package always
// records a fact, resolved or not, rather than dropping a field it
// couldn't resolve.
//
// KMSKeyID and CloudWatchLogsLogGroupARN are collected but deliberately
// carry no Provenance of their own and map to no control yet - see
// cloudtrail_ir.go's doc comment for why (the same "collect now, map
// later once reviewed" treatment s3.go's BucketLogging field got before
// any Terraform-side precedent existed for it, per ADR 0008). Retention
// (FR-3.2's third named concern, alongside configuration and log file
// integrity validation) is not collected at all: it lives on the log
// destination - the S3 bucket's lifecycle policy, or CloudWatch Logs'
// own retention-in-days setting - a different collection surface this
// file does not touch.
type Trail struct {
	Name                      string        `json:"name"`
	Config                    *TrailConfig  `json:"config"`
	Logging                   *TrailLogging `json:"logging"`
	KMSKeyID                  string        `json:"kms_key_id,omitempty"`
	CloudWatchLogsLogGroupARN string        `json:"cloudwatch_logs_log_group_arn,omitempty"`
}

// TrailConfig is a trail's multi-region/organization-trail scope and
// whether log file integrity validation is enabled - all three come
// from the same DescribeTrails response, so they share one Provenance.
// Meaningful only when Provenance.Confidence is Deterministic.
type TrailConfig struct {
	IsMultiRegionTrail       bool              `json:"is_multi_region_trail"`
	IsOrganizationTrail      bool              `json:"is_organization_trail"`
	LogFileValidationEnabled bool              `json:"log_file_validation_enabled"`
	Provenance               provenance.Record `json:"provenance"`
}

// TrailLogging is whether a trail is actively logging as of when this
// collector ran (GetTrailStatus's IsLogging - a live status check,
// independent of whether the trail is merely configured to exist).
// Meaningful only when Provenance.Confidence is Deterministic.
type TrailLogging struct {
	IsLogging  bool              `json:"is_logging"`
	Provenance provenance.Record `json:"provenance"`
}

// CloudTrailGraph is every trail this collector found in the caller's
// configured Region, per FR-3.2.
type CloudTrailGraph struct {
	Trails []Trail `json:"trails"`
}

// CollectCloudTrail describes every trail in the account/Region client
// is configured for, then reads each one's live logging status
// concurrently, up to maxConcurrentItems at a time (collectConcurrent,
// concurrent.go).
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// see CollectS3's doc comment (s3.go) for why this package never calls
// time.Now() itself.
func CollectCloudTrail(ctx context.Context, client CloudTrailAPI, observedAt time.Time) (*CloudTrailGraph, error) {
	trails, err := describeTrails(ctx, client, observedAt)
	if err != nil {
		return nil, fmt.Errorf("aws: cloudtrail: describe trails: %w", err)
	}

	names := make([]string, len(trails))
	for i, t := range trails {
		names[i] = t.Name
	}
	logging, err := collectConcurrent(ctx, names, func(ctx context.Context, name string) TrailLogging {
		return *collectTrailLogging(ctx, client, name, observedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("aws: cloudtrail: collect trail status: %w", err)
	}
	for i := range trails {
		trails[i].Logging = &logging[i]
	}

	return &CloudTrailGraph{Trails: trails}, nil
}

// describeTrails calls DescribeTrails once for every trail in the
// caller's Region, sorted by name for the same reproducibility reasons
// listBucketNames documents (s3.go).
//
// IncludeShadowTrails is explicitly set to false. Left at its API
// default (true, or unset), a multi-region trail created in a different
// Region - or an organization trail replicated into a member account -
// comes back as an extra "shadow" entry for the current Region on top
// of its real one, which would produce two IR nodes with two different
// awsNodeID values for what is actually the same trail. false is not
// simply "the safer of two options": it is the specific setting whose
// own documented behavior is "information for all trails in the current
// Region is returned" with no shadow duplication, which is exactly what
// this collector needs.
func describeTrails(ctx context.Context, client CloudTrailAPI, observedAt time.Time) ([]Trail, error) {
	const api = "cloudtrail:DescribeTrails"
	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: boolPtr(false)})
	if err != nil {
		return nil, err
	}

	var trails []Trail
	for _, t := range out.TrailList {
		if t.Name == nil {
			continue
		}
		trail := Trail{Name: *t.Name}
		if t.KmsKeyId != nil {
			trail.KMSKeyID = *t.KmsKeyId
		}
		if t.CloudWatchLogsLogGroupArn != nil {
			trail.CloudWatchLogsLogGroupARN = *t.CloudWatchLogsLogGroupArn
		}
		if t.IsMultiRegionTrail == nil || t.IsOrganizationTrail == nil || t.LogFileValidationEnabled == nil {
			trail.Config = &TrailConfig{
				Provenance: cloudTrailUnresolvedRecord(trail.Name, api, "response had an incomplete trail configuration", observedAt),
			}
		} else {
			trail.Config = &TrailConfig{
				IsMultiRegionTrail:       *t.IsMultiRegionTrail,
				IsOrganizationTrail:      *t.IsOrganizationTrail,
				LogFileValidationEnabled: *t.LogFileValidationEnabled,
				Provenance:               cloudTrailRecord(trail.Name, api, observedAt),
			}
		}
		trails = append(trails, trail)
	}
	sort.Slice(trails, func(i, j int) bool { return trails[i].Name < trails[j].Name })
	return trails, nil
}

// cloudTrailRecord and cloudTrailUnresolvedRecord are thin wrappers
// around this package's shared observedRecord/unresolvedRecord
// (provenance.go) - see s3.go's s3Record/s3UnresolvedRecord for the same
// pattern.
func cloudTrailRecord(trail, api string, observedAt time.Time) provenance.Record {
	return observedRecord(CloudTrailCollectorVersion, api, map[string]string{"trail": trail}, observedAt)
}

func cloudTrailUnresolvedRecord(trail, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(CloudTrailCollectorVersion, api, reason, map[string]string{"trail": trail}, observedAt)
}

// collectTrailLogging reads whether trail is actively logging right
// now. Unlike describeTrails' config fields, this is never ambiguous on
// a successful call - GetTrailStatus always returns IsLogging - so a
// real API error (a permissions gap, an ARN required for an
// organization trail that this collector did not supply, per
// GetTrailStatusInput's own documented ARN requirement for shadow/org
// trails - not a concern here since describeTrails excludes shadow
// trails) is the only unresolved case.
func collectTrailLogging(ctx context.Context, client CloudTrailAPI, name string, observedAt time.Time) *TrailLogging {
	const api = "cloudtrail:GetTrailStatus"
	out, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: &name})
	if err != nil {
		return &TrailLogging{Provenance: cloudTrailUnresolvedRecord(name, api, err.Error(), observedAt)}
	}
	if out.IsLogging == nil {
		return &TrailLogging{Provenance: cloudTrailUnresolvedRecord(name, api, "response had no logging status", observedAt)}
	}
	return &TrailLogging{IsLogging: *out.IsLogging, Provenance: cloudTrailRecord(name, api, observedAt)}
}

func boolPtr(b bool) *bool { return &b }
