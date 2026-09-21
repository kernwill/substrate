package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// GuardDutyCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const GuardDutyCollectorVersion = "aws-guardduty/v0.1.0"

// GuardDutyAPI names only the GuardDuty operations this file's
// collector calls. See this package's doc.go for why this is a narrow,
// hand-written interface rather than the full *guardduty.Client
// (FR-3.10's fixture-based testing).
type GuardDutyAPI interface {
	ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

// Detector is one collected GuardDuty detector - FR-3.6's enablement
// half for GuardDuty specifically (findings - the actual threat
// detections GuardDuty produces - are a separate, larger, paginated
// data model this collector does not attempt yet, tracked as its own
// follow-on rather than bundled in here).
//
// Present is a real, resolved measurement, not an absence: AWS allows
// at most one GuardDuty detector per account per Region, so
// ListDetectors returning zero IDs is not "we couldn't check" - it's a
// definitive "GuardDuty has never been enabled here," exactly the kind
// of confirmed-negative fact IAMUser's own ConsolePassword field already
// establishes shouldn't collapse into silence (no node at all) the way
// an ambiguous API error would.
type Detector struct {
	Present                    bool   `json:"present"`
	DetectorID                 string `json:"detector_id,omitempty"`
	Enabled                    bool   `json:"enabled"`
	FindingPublishingFrequency string `json:"finding_publishing_frequency,omitempty"`

	Provenance provenance.Record `json:"provenance"`
}

// GuardDutyGraph is this account/Region's GuardDuty enablement state.
// Detectors always has at least one entry after a successful collection
// run - a synthetic Present:false entry when ListDetectors finds
// nothing, per Detector's own doc comment on why that's a real fact,
// not silence.
type GuardDutyGraph struct {
	Detectors []Detector `json:"detectors"`
}

// CollectGuardDuty lists every detector in the caller's account/Region
// (normally zero or one - GuardDuty's own documented limit), then reads
// each one's live status. The account-wide list call plus per-item
// detail fan-out mirrors aws.CollectCloudTrail's shape exactly (list
// trails, then GetTrailStatus per trail).
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectGuardDuty(ctx context.Context, client GuardDutyAPI, observedAt time.Time) (*GuardDutyGraph, error) {
	ids, err := listDetectorIDs(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: guardduty: list detectors: %w", err)
	}

	if len(ids) == 0 {
		return &GuardDutyGraph{Detectors: []Detector{{
			Present:    false,
			Provenance: guardDutyRecord("", "guardduty:ListDetectors", observedAt),
		}}}, nil
	}

	detectors, err := collectConcurrent(ctx, ids, func(ctx context.Context, id string) Detector {
		return *collectDetector(ctx, client, id, observedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("aws: guardduty: collect detectors: %w", err)
	}

	sort.Slice(detectors, func(i, j int) bool { return detectors[i].DetectorID < detectors[j].DetectorID })
	return &GuardDutyGraph{Detectors: detectors}, nil
}

// listDetectorIDs pages through every detector ID in the account/Region,
// sorted for the same reproducibility reasons listBucketNames documents
// (s3.go).
func listDetectorIDs(ctx context.Context, client GuardDutyAPI) ([]string, error) {
	paginator := guardduty.NewListDetectorsPaginator(client, &guardduty.ListDetectorsInput{})
	var ids []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		ids = append(ids, page.DetectorIds...)
	}
	sort.Strings(ids)
	return ids, nil
}

// collectDetector reads one detector's live status. A GetDetector
// failure (permissions, or the detector was deleted between the list
// and get calls) is genuinely unresolved, not a real "disabled" -
// unlike Detector.Present's own zero-detectors case, this is an
// ambiguous API failure, not a confirmed absence.
func collectDetector(ctx context.Context, client GuardDutyAPI, id string, observedAt time.Time) *Detector {
	const api = "guardduty:GetDetector"
	out, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &id})
	if err != nil {
		return &Detector{
			Present:    true,
			DetectorID: id,
			Provenance: guardDutyUnresolvedRecord(id, api, err.Error(), observedAt),
		}
	}
	return &Detector{
		Present:                    true,
		DetectorID:                 id,
		Enabled:                    out.Status == types.DetectorStatusEnabled,
		FindingPublishingFrequency: string(out.FindingPublishingFrequency),
		Provenance:                 guardDutyRecord(id, api, observedAt),
	}
}

// guardDutyRecord and guardDutyUnresolvedRecord are thin wrappers
// around this package's shared observedRecord/unresolvedRecord
// (provenance.go), fixing this file's own collector version - same
// pattern as securityGroupRecord/cloudTrailRecord.
func guardDutyRecord(detectorID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(GuardDutyCollectorVersion, api, map[string]string{"detector_id": detectorID}, observedAt)
}

func guardDutyUnresolvedRecord(detectorID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(GuardDutyCollectorVersion, api, reason, map[string]string{"detector_id": detectorID}, observedAt)
}
