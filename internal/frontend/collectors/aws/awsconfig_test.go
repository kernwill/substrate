package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// fakeConfig implements ConfigAPI by serving canned data loaded from
// this package's testdata fixtures (FR-3.10) instead of calling AWS.
type fakeConfig struct {
	statuses []types.ConfigurationRecorderStatus
}

func loadFakeConfig(t *testing.T) *fakeConfig {
	t.Helper()
	var raw []struct {
		Name       string `json:"name"`
		Recording  bool   `json:"recording"`
		LastStatus string `json:"last_status"`
	}
	readTestdataJSON(t, "config_recorder_status.json", &raw)

	f := &fakeConfig{}
	for _, s := range raw {
		f.statuses = append(f.statuses, types.ConfigurationRecorderStatus{
			Name:       strPtr(s.Name),
			Recording:  s.Recording,
			LastStatus: types.RecorderStatus(s.LastStatus),
		})
	}
	return f
}

func (f *fakeConfig) DescribeConfigurationRecorderStatus(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: f.statuses}, nil
}

func TestCollectConfig(t *testing.T) {
	client := loadFakeConfig(t)
	graph, err := CollectConfig(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectConfig: %v", err)
	}
	if len(graph.Recorders) != 1 {
		t.Fatalf("got %d recorders, want 1", len(graph.Recorders))
	}
	r := graph.Recorders[0]
	if r.Provenance.Confidence != "deterministic" {
		t.Fatalf("Provenance.Confidence = %v, want deterministic", r.Provenance.Confidence)
	}
	if !r.Present || !r.Recording {
		t.Errorf("recorder = %+v, want Present=true Recording=true", r)
	}
	if r.Name != "default" || r.LastStatus != "Success" {
		t.Errorf("recorder = %+v, want name default, last_status Success", r)
	}
}

// TestCollectConfigNoRecorders confirms an account with AWS Config
// never set up produces one resolved Present:false fact, not silence -
// see ConfigRecorder's own doc comment for why that distinction
// matters, mirroring GuardDuty's identical discipline.
func TestCollectConfigNoRecorders(t *testing.T) {
	client := &fakeConfig{}
	graph, err := CollectConfig(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectConfig: %v", err)
	}
	if len(graph.Recorders) != 1 {
		t.Fatalf("got %d recorders, want 1 synthetic Present:false entry", len(graph.Recorders))
	}
	r := graph.Recorders[0]
	if r.Present {
		t.Error("Present = true, want false (no recorder exists)")
	}
	if r.Provenance.Confidence != "deterministic" {
		t.Errorf("Provenance.Confidence = %v, want deterministic - a confirmed zero is resolved, not unresolved", r.Provenance.Confidence)
	}
}
