package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// fakeCloudTrail implements CloudTrailAPI by serving canned data loaded
// from this package's testdata fixtures (FR-3.10) instead of calling
// AWS.
type fakeCloudTrail struct {
	trails map[string]struct {
		Incomplete                bool
		IsMultiRegionTrail        bool
		IsOrganizationTrail       bool
		LogFileValidationEnabled  bool
		KMSKeyID                  string
		CloudWatchLogsLogGroupARN string
	}
	statuses map[string]struct {
		IsLogging bool
		Err       string
	}
}

func loadFakeCloudTrail(t *testing.T) *fakeCloudTrail {
	t.Helper()
	readJSON := func(name string, v any) { readTestdataJSON(t, name, v) }

	f := &fakeCloudTrail{}

	var trailsRaw map[string]struct {
		Incomplete                bool   `json:"incomplete"`
		IsMultiRegionTrail        bool   `json:"is_multi_region_trail"`
		IsOrganizationTrail       bool   `json:"is_organization_trail"`
		LogFileValidationEnabled  bool   `json:"log_file_validation_enabled"`
		KMSKeyID                  string `json:"kms_key_id"`
		CloudWatchLogsLogGroupARN string `json:"cloudwatch_logs_log_group_arn"`
	}
	readJSON("cloudtrail_trails.json", &trailsRaw)
	f.trails = make(map[string]struct {
		Incomplete                bool
		IsMultiRegionTrail        bool
		IsOrganizationTrail       bool
		LogFileValidationEnabled  bool
		KMSKeyID                  string
		CloudWatchLogsLogGroupARN string
	}, len(trailsRaw))
	for k, v := range trailsRaw {
		f.trails[k] = struct {
			Incomplete                bool
			IsMultiRegionTrail        bool
			IsOrganizationTrail       bool
			LogFileValidationEnabled  bool
			KMSKeyID                  string
			CloudWatchLogsLogGroupARN string
		}{v.Incomplete, v.IsMultiRegionTrail, v.IsOrganizationTrail, v.LogFileValidationEnabled, v.KMSKeyID, v.CloudWatchLogsLogGroupARN}
	}

	var statusesRaw map[string]struct {
		IsLogging bool   `json:"is_logging"`
		Error     string `json:"error"`
	}
	readJSON("cloudtrail_status.json", &statusesRaw)
	f.statuses = make(map[string]struct {
		IsLogging bool
		Err       string
	}, len(statusesRaw))
	for k, v := range statusesRaw {
		f.statuses[k] = struct {
			IsLogging bool
			Err       string
		}{v.IsLogging, v.Error}
	}

	return f
}

func (f *fakeCloudTrail) DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	// IncludeShadowTrails must be explicitly false - see describeTrails'
	// own doc comment for why a shadow-trail-inclusive call would be
	// the wrong request entirely, not just a less efficient one.
	if params.IncludeShadowTrails == nil || *params.IncludeShadowTrails != false {
		return nil, errors.New("fakeCloudTrail: DescribeTrails called without IncludeShadowTrails=false")
	}
	out := &cloudtrail.DescribeTrailsOutput{}
	for name, cfg := range f.trails {
		name := name
		trail := types.Trail{Name: &name}
		if !cfg.Incomplete {
			isMultiRegion, isOrg, validation := cfg.IsMultiRegionTrail, cfg.IsOrganizationTrail, cfg.LogFileValidationEnabled
			trail.IsMultiRegionTrail = &isMultiRegion
			trail.IsOrganizationTrail = &isOrg
			trail.LogFileValidationEnabled = &validation
		}
		if cfg.KMSKeyID != "" {
			kmsKeyID := cfg.KMSKeyID
			trail.KmsKeyId = &kmsKeyID
		}
		if cfg.CloudWatchLogsLogGroupARN != "" {
			logGroupARN := cfg.CloudWatchLogsLogGroupARN
			trail.CloudWatchLogsLogGroupArn = &logGroupARN
		}
		out.TrailList = append(out.TrailList, trail)
	}
	return out, nil
}

func (f *fakeCloudTrail) GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	s, ok := f.statuses[*params.Name]
	if !ok {
		return &cloudtrail.GetTrailStatusOutput{}, nil
	}
	if s.Err != "" {
		return nil, errors.New(s.Err)
	}
	isLogging := s.IsLogging
	return &cloudtrail.GetTrailStatusOutput{IsLogging: &isLogging}, nil
}

func TestCollectCloudTrail(t *testing.T) {
	client := loadFakeCloudTrail(t)
	graph, err := CollectCloudTrail(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectCloudTrail: %v", err)
	}
	if len(graph.Trails) != 4 {
		t.Fatalf("got %d trails, want 4", len(graph.Trails))
	}

	byName := make(map[string]Trail, len(graph.Trails))
	for _, tr := range graph.Trails {
		byName[tr.Name] = tr
	}

	alpha := byName["alpha"]
	if alpha.Config == nil || alpha.Config.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("alpha.Config = %+v, want resolved", alpha.Config)
	}
	if !alpha.Config.IsMultiRegionTrail || !alpha.Config.IsOrganizationTrail || !alpha.Config.LogFileValidationEnabled {
		t.Errorf("alpha.Config = %+v, want all three flags true", alpha.Config)
	}
	if alpha.KMSKeyID == "" || alpha.CloudWatchLogsLogGroupARN == "" {
		t.Errorf("alpha KMSKeyID/CloudWatchLogsLogGroupARN = %q/%q, want both populated (collected even though unmapped)", alpha.KMSKeyID, alpha.CloudWatchLogsLogGroupARN)
	}
	if alpha.Logging == nil || alpha.Logging.Provenance.Confidence != provenance.Deterministic || !alpha.Logging.IsLogging {
		t.Errorf("alpha.Logging = %+v, want resolved and true", alpha.Logging)
	}

	beta := byName["beta"]
	if beta.Config == nil || beta.Config.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("beta.Config = %+v, want resolved", beta.Config)
	}
	if beta.Config.IsMultiRegionTrail || beta.Config.IsOrganizationTrail || beta.Config.LogFileValidationEnabled {
		t.Errorf("beta.Config = %+v, want all three flags false", beta.Config)
	}
	if beta.Logging == nil || beta.Logging.Provenance.Confidence != provenance.Deterministic || beta.Logging.IsLogging {
		t.Errorf("beta.Logging = %+v, want resolved and false (a resolved false, not an absence)", beta.Logging)
	}

	delta := byName["delta"]
	if delta.Config == nil || delta.Config.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("delta.Config = %+v, want Unresolved (incomplete DescribeTrails response)", delta.Config)
	}
	if delta.Config != nil && delta.Config.Provenance.UnresolvedReason == "" {
		t.Error("delta.Config.Provenance.UnresolvedReason is empty")
	}
	if delta.Logging == nil || delta.Logging.Provenance.Confidence != provenance.Deterministic {
		t.Errorf("delta.Logging = %+v, want resolved (GetTrailStatus succeeded independently of the config gap)", delta.Logging)
	}

	gamma := byName["gamma"]
	if gamma.Config == nil || gamma.Config.Provenance.Confidence != provenance.Deterministic {
		t.Errorf("gamma.Config = %+v, want resolved", gamma.Config)
	}
	if gamma.Logging == nil || gamma.Logging.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("gamma.Logging = %+v, want Unresolved (simulated GetTrailStatus API error)", gamma.Logging)
	}
	if gamma.Logging != nil && gamma.Logging.Provenance.UnresolvedReason == "" {
		t.Error("gamma.Logging.Provenance.UnresolvedReason is empty")
	}
}

// TestCollectCloudTrailEveryFieldNonNil mirrors
// TestCollectS3EveryFieldNonNil/TestCollectIAMEveryFieldNonNil: no
// trail's Config or Logging is ever a bare nil, even when nothing about
// it resolved.
func TestCollectCloudTrailEveryFieldNonNil(t *testing.T) {
	client := loadFakeCloudTrail(t)
	graph, err := CollectCloudTrail(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectCloudTrail: %v", err)
	}
	for _, tr := range graph.Trails {
		if tr.Config == nil {
			t.Errorf("%s.Config is nil, want a non-nil fact", tr.Name)
		}
		if tr.Logging == nil {
			t.Errorf("%s.Logging is nil, want a non-nil fact", tr.Name)
		}
	}
}

func TestCollectCloudTrailSortedByName(t *testing.T) {
	client := loadFakeCloudTrail(t)
	graph, err := CollectCloudTrail(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectCloudTrail: %v", err)
	}
	for i := 1; i < len(graph.Trails); i++ {
		if graph.Trails[i-1].Name >= graph.Trails[i].Name {
			t.Fatalf("trails not sorted: %q >= %q", graph.Trails[i-1].Name, graph.Trails[i].Name)
		}
	}
}
