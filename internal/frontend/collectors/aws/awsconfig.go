package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/kernwill/substrate/internal/provenance"
)

// ConfigCollectorVersion is this file's own collector version (FR-4.1),
// independent of every other collector version in this package. Named
// for the file (awsconfig.go, not config.go) and the constant
// (ConfigCollectorVersion, not AWSConfigCollectorVersion) to keep the
// Go identifier short - "aws." already disambiguates the package, the
// same reasoning every other *CollectorVersion constant here already
// follows - while the file itself is named awsconfig.go specifically to
// avoid reading as this codebase's many other uses of "config"
// (Terraform config, aws-sdk-go-v2/config, Okta's own Config type).
const ConfigCollectorVersion = "aws-config/v0.1.0"

// ConfigAPI names only the AWS Config operation this file's collector
// calls. See this package's doc.go for why this is a narrow,
// hand-written interface rather than the full *configservice.Client
// (FR-3.10's fixture-based testing).
type ConfigAPI interface {
	DescribeConfigurationRecorderStatus(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
}

// ConfigRecorder is one collected AWS Config recorder - FR-3.6's
// enablement half for AWS Config specifically (findings - Config Rules'
// actual compliance evaluation results - are a separate, larger data
// model this collector does not attempt yet, the same scoping
// GuardDuty's own enablement-first pass established).
//
// Present is a real, resolved measurement, not an absence: a modern AWS
// account has at most one customer-managed configuration recorder per
// account per Region, so DescribeConfigurationRecorderStatus returning
// zero entries is not "we couldn't check" - it's a definitive "AWS
// Config has never been set up here," the same confirmed-negative shape
// aws.Detector's own Present field already establishes for GuardDuty.
type ConfigRecorder struct {
	Present    bool   `json:"present"`
	Name       string `json:"name,omitempty"`
	Recording  bool   `json:"recording"`
	LastStatus string `json:"last_status,omitempty"`

	Provenance provenance.Record `json:"provenance"`
}

// ConfigGraph is this account/Region's AWS Config enablement state.
// Recorders always has at least one entry after a successful collection
// run - a synthetic Present:false entry when the status call finds
// nothing, per ConfigRecorder's own doc comment.
type ConfigGraph struct {
	Recorders []ConfigRecorder `json:"recorders"`
}

// CollectConfig reads every configuration recorder's live status in the
// caller's account/Region - a single call, simpler than
// aws.CollectGuardDuty's list-then-per-item-detail shape:
// DescribeConfigurationRecorderStatus already returns each recorder's
// name, Recording bool, and last status inline, with no second detail
// call needed.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectConfig(ctx context.Context, client ConfigAPI, observedAt time.Time) (*ConfigGraph, error) {
	out, err := client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, fmt.Errorf("aws: config: describe configuration recorder status: %w", err)
	}

	if len(out.ConfigurationRecordersStatus) == 0 {
		return &ConfigGraph{Recorders: []ConfigRecorder{{
			Present:    false,
			Provenance: configRecord("", observedAt),
		}}}, nil
	}

	recorders := make([]ConfigRecorder, 0, len(out.ConfigurationRecordersStatus))
	for _, s := range out.ConfigurationRecordersStatus {
		recorders = append(recorders, ConfigRecorder{
			Present:    true,
			Name:       valueOrEmpty(s.Name),
			Recording:  s.Recording,
			LastStatus: string(s.LastStatus),
			Provenance: configRecord(valueOrEmpty(s.Name), observedAt),
		})
	}

	sort.Slice(recorders, func(i, j int) bool { return recorders[i].Name < recorders[j].Name })
	return &ConfigGraph{Recorders: recorders}, nil
}

// configRecord is a thin wrapper around this package's shared
// observedRecord (provenance.go), fixing this file's own collector
// version - same pattern as guardDutyRecord/securityGroupRecord. There
// is no unresolved case for this collector: the status call either
// succeeds (every recorder it returns is fully resolved - AWS Config
// never returns a partial ConfigurationRecorderStatus) or fails
// outright, which CollectConfig already surfaces as a real error,
// mirroring securityGroupRecord's own reasoning for the same shape.
func configRecord(name string, observedAt time.Time) provenance.Record {
	return observedRecord(ConfigCollectorVersion, "config:DescribeConfigurationRecorderStatus", map[string]string{"recorder_name": name}, observedAt)
}
