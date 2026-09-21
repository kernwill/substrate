package okta

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

var (
	testSince = time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	testUntil = time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
)

func TestCollectProvisioningEvents(t *testing.T) {
	client := newFakePolicyEndpoint().withLogEvents(t, "provisioning_events.json")
	graph, err := CollectProvisioningEvents(context.Background(), client, testObservedAt, testSince, testUntil)
	if err != nil {
		t.Fatalf("CollectProvisioningEvents: %v", err)
	}
	if len(graph.Events) != 3 {
		t.Fatalf("got %d events, want 3", len(graph.Events))
	}

	byID := make(map[string]ProvisioningEvent, len(graph.Events))
	for _, e := range graph.Events {
		byID[e.ID] = e
	}

	create := byID["evt-1"]
	if create.Provenance.Confidence != provenance.Deterministic {
		t.Fatalf("evt-1.Provenance.Confidence = %v, want Deterministic", create.Provenance.Confidence)
	}
	if create.EventType != "user.lifecycle.create" {
		t.Errorf("evt-1.EventType = %q, want user.lifecycle.create", create.EventType)
	}
	if create.Outcome != "SUCCESS" {
		t.Errorf("evt-1.Outcome = %q, want SUCCESS", create.Outcome)
	}
	if create.ActorName != "Jane Admin" {
		t.Errorf("evt-1.ActorName = %q, want Jane Admin", create.ActorName)
	}
	if len(create.TargetIDs) != 1 || create.TargetIDs[0] != "user-1" {
		t.Errorf("evt-1.TargetIDs = %v, want [user-1]", create.TargetIDs)
	}

	deactivate := byID["evt-2"]
	if deactivate.EventType != "user.lifecycle.deactivate" {
		t.Errorf("evt-2.EventType = %q, want user.lifecycle.deactivate", deactivate.EventType)
	}

	// The malformed event (empty uuid) collapses to the "" key - its
	// own Provenance must be Unresolved, not silently dropped from the
	// graph entirely.
	malformed, ok := byID[""]
	if !ok {
		t.Fatal("no entry for the malformed (empty-uuid) event - it must still be recorded, unresolved")
	}
	if malformed.Provenance.Confidence != provenance.Unresolved {
		t.Errorf("malformed event Provenance.Confidence = %v, want Unresolved", malformed.Provenance.Confidence)
	}
	if malformed.Provenance.UnresolvedReason == "" {
		t.Error("malformed event Provenance.UnresolvedReason is empty")
	}
}

func TestCollectProvisioningEventsSortedByID(t *testing.T) {
	client := newFakePolicyEndpoint().withLogEvents(t, "provisioning_events.json")
	graph, err := CollectProvisioningEvents(context.Background(), client, testObservedAt, testSince, testUntil)
	if err != nil {
		t.Fatalf("CollectProvisioningEvents: %v", err)
	}
	for i := 1; i < len(graph.Events); i++ {
		if graph.Events[i-1].ID >= graph.Events[i].ID {
			t.Fatalf("events not sorted: %q >= %q", graph.Events[i-1].ID, graph.Events[i].ID)
		}
	}
}

func TestCollectProvisioningEventsPropagatesListError(t *testing.T) {
	client := newFakePolicyEndpoint().withLogEventsError(errors.New("simulated system log failure"))
	if _, err := CollectProvisioningEvents(context.Background(), client, testObservedAt, testSince, testUntil); err == nil {
		t.Fatal("CollectProvisioningEvents succeeded, want an error when ListSystemLogEvents fails")
	}
}
