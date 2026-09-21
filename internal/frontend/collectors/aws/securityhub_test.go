package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// fakeSecurityHub implements SecurityHubAPI, returning either a canned
// success response or a canned error, set directly by the test rather
// than loaded from a JSON fixture - there's exactly one call this
// collector makes, so a small Go literal per test case is clearer than
// a fixture file for three scenarios (subscribed, confirmed
// not-subscribed, and a genuine error).
type fakeSecurityHub struct {
	out *securityhub.DescribeHubOutput
	err error
}

func (f *fakeSecurityHub) DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}

func TestCollectSecurityHub(t *testing.T) {
	client := &fakeSecurityHub{out: &securityhub.DescribeHubOutput{
		HubArn:             strPtr("arn:aws:securityhub:us-east-1:123456789012:hub/default"),
		SubscribedAt:       strPtr("2026-01-01T00:00:00.000Z"),
		AutoEnableControls: boolPtr(true),
	}}
	graph, err := CollectSecurityHub(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityHub: %v", err)
	}
	if len(graph.Hubs) != 1 {
		t.Fatalf("got %d hubs, want 1", len(graph.Hubs))
	}
	h := graph.Hubs[0]
	if h.Provenance.Confidence != "deterministic" {
		t.Fatalf("Provenance.Confidence = %v, want deterministic", h.Provenance.Confidence)
	}
	if !h.Present || !h.AutoEnableControls {
		t.Errorf("hub = %+v, want Present=true AutoEnableControls=true", h)
	}
	if h.HubARN != "arn:aws:securityhub:us-east-1:123456789012:hub/default" {
		t.Errorf("HubARN = %q, want the fixture ARN", h.HubARN)
	}
}

// TestCollectSecurityHubNotSubscribed confirms the specific, documented
// "not subscribed" InvalidAccessException is treated as a resolved
// Present:false fact, not an error - see notSubscribedMessage's own doc
// comment.
func TestCollectSecurityHubNotSubscribed(t *testing.T) {
	client := &fakeSecurityHub{err: &types.InvalidAccessException{
		Message: strPtr("Account 123456789012 is not subscribed to AWS Security Hub"),
	}}
	graph, err := CollectSecurityHub(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityHub: %v", err)
	}
	if len(graph.Hubs) != 1 {
		t.Fatalf("got %d hubs, want 1 synthetic Present:false entry", len(graph.Hubs))
	}
	h := graph.Hubs[0]
	if h.Present {
		t.Error("Present = true, want false (account not subscribed)")
	}
	if h.Provenance.Confidence != "deterministic" {
		t.Errorf("Provenance.Confidence = %v, want deterministic - a confirmed not-subscribed state is resolved, not unresolved", h.Provenance.Confidence)
	}
}

// TestCollectSecurityHubOtherInvalidAccessFailsLoudly confirms an
// InvalidAccessException with a DIFFERENT message (a real access
// problem, not "not subscribed") is NOT collapsed into a confirmed
// absence - it must propagate as a real error, the same "don't assume
// every error of this type means the same thing" discipline
// docs/adr/0008 applies to IAM's NoSuchEntity nuance.
func TestCollectSecurityHubOtherInvalidAccessFailsLoudly(t *testing.T) {
	client := &fakeSecurityHub{err: &types.InvalidAccessException{
		Message: strPtr("Account 123456789012 is not an administrator for this organization"),
	}}
	if _, err := CollectSecurityHub(context.Background(), client, testObservedAt); err == nil {
		t.Fatal("CollectSecurityHub succeeded, want an error for a non-'not subscribed' InvalidAccessException")
	}
}

func TestCollectSecurityHubGenericErrorFailsLoudly(t *testing.T) {
	client := &fakeSecurityHub{err: errors.New("simulated network failure")}
	if _, err := CollectSecurityHub(context.Background(), client, testObservedAt); err == nil {
		t.Fatal("CollectSecurityHub succeeded, want an error for a generic failure")
	}
}
