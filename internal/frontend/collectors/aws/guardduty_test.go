package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// fakeGuardDuty implements GuardDutyAPI by serving canned data loaded
// from this package's testdata fixtures (FR-3.10) instead of calling
// AWS.
type fakeGuardDuty struct {
	detectors map[string]struct {
		Status                     string
		FindingPublishingFrequency string
		Err                        string
	}
}

func loadFakeGuardDuty(t *testing.T) *fakeGuardDuty {
	t.Helper()
	var raw map[string]struct {
		Status                     string `json:"status"`
		FindingPublishingFrequency string `json:"finding_publishing_frequency"`
		Error                      string `json:"error"`
	}
	readTestdataJSON(t, "guardduty_detectors.json", &raw)

	f := &fakeGuardDuty{detectors: make(map[string]struct {
		Status                     string
		FindingPublishingFrequency string
		Err                        string
	}, len(raw))}
	for k, v := range raw {
		f.detectors[k] = struct {
			Status                     string
			FindingPublishingFrequency string
			Err                        string
		}{v.Status, v.FindingPublishingFrequency, v.Error}
	}
	return f
}

func (f *fakeGuardDuty) ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	ids := make([]string, 0, len(f.detectors))
	for id := range f.detectors {
		ids = append(ids, id)
	}
	return &guardduty.ListDetectorsOutput{DetectorIds: ids}, nil
}

func (f *fakeGuardDuty) GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	d, ok := f.detectors[*params.DetectorId]
	if !ok {
		return nil, errors.New("fakeGuardDuty: no fixture registered for detector " + *params.DetectorId)
	}
	if d.Err != "" {
		return nil, errors.New(d.Err)
	}
	status := types.DetectorStatusDisabled
	if d.Status == "ENABLED" {
		status = types.DetectorStatusEnabled
	}
	return &guardduty.GetDetectorOutput{
		Status:                     status,
		ServiceRole:                strPtr("arn:aws:iam::123456789012:role/aws-service-role/guardduty"),
		FindingPublishingFrequency: types.FindingPublishingFrequency(d.FindingPublishingFrequency),
	}, nil
}

func TestCollectGuardDuty(t *testing.T) {
	client := loadFakeGuardDuty(t)
	graph, err := CollectGuardDuty(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectGuardDuty: %v", err)
	}
	if len(graph.Detectors) != 3 {
		t.Fatalf("got %d detectors, want 3", len(graph.Detectors))
	}

	byID := make(map[string]Detector, len(graph.Detectors))
	for _, d := range graph.Detectors {
		byID[d.DetectorID] = d
	}

	good := byID["detector-good"]
	if good.Provenance.Confidence != "deterministic" {
		t.Fatalf("detector-good.Provenance.Confidence = %v, want deterministic", good.Provenance.Confidence)
	}
	if !good.Present || !good.Enabled {
		t.Errorf("detector-good = %+v, want Present=true Enabled=true", good)
	}
	if good.FindingPublishingFrequency != "FIFTEEN_MINUTES" {
		t.Errorf("detector-good.FindingPublishingFrequency = %q, want FIFTEEN_MINUTES", good.FindingPublishingFrequency)
	}

	off := byID["detector-off"]
	if !off.Present || off.Enabled {
		t.Errorf("detector-off = %+v, want Present=true Enabled=false (a resolved false, not an absence)", off)
	}

	errDetector := byID["detector-error"]
	if errDetector.Provenance.Confidence != "unresolved" {
		t.Fatalf("detector-error.Provenance.Confidence = %v, want unresolved", errDetector.Provenance.Confidence)
	}
	if errDetector.Provenance.UnresolvedReason == "" {
		t.Error("detector-error.Provenance.UnresolvedReason is empty")
	}
}

func TestCollectGuardDutySortedByID(t *testing.T) {
	client := loadFakeGuardDuty(t)
	graph, err := CollectGuardDuty(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectGuardDuty: %v", err)
	}
	for i := 1; i < len(graph.Detectors); i++ {
		if graph.Detectors[i-1].DetectorID >= graph.Detectors[i].DetectorID {
			t.Fatalf("detectors not sorted: %q >= %q", graph.Detectors[i-1].DetectorID, graph.Detectors[i].DetectorID)
		}
	}
}

// TestCollectGuardDutyNoDetectors confirms a region with GuardDuty never
// enabled produces one resolved Present:false fact, not silence - see
// Detector's own doc comment for why that distinction matters.
func TestCollectGuardDutyNoDetectors(t *testing.T) {
	client := &fakeGuardDuty{detectors: map[string]struct {
		Status                     string
		FindingPublishingFrequency string
		Err                        string
	}{}}
	graph, err := CollectGuardDuty(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectGuardDuty: %v", err)
	}
	if len(graph.Detectors) != 1 {
		t.Fatalf("got %d detectors, want 1 synthetic Present:false entry", len(graph.Detectors))
	}
	d := graph.Detectors[0]
	if d.Present {
		t.Error("Present = true, want false (no detector exists)")
	}
	if d.Provenance.Confidence != "deterministic" {
		t.Errorf("Provenance.Confidence = %v, want deterministic - a confirmed zero is resolved, not unresolved", d.Provenance.Confidence)
	}
}
