package okta

import (
	"context"
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

func TestProvisioningEventsToIR(t *testing.T) {
	client := newFakePolicyEndpoint().withLogEvents(t, "provisioning_events.json")
	graph, err := CollectProvisioningEvents(context.Background(), client, testObservedAt, testSince, testUntil)
	if err != nil {
		t.Fatalf("CollectProvisioningEvents: %v", err)
	}
	irGraph, err := ProvisioningEventsToIR(graph)
	if err != nil {
		t.Fatalf("ProvisioningEventsToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// evt-1 and evt-2 resolved -> 2 nodes; the malformed (empty-uuid)
	// event never resolved -> 0 nodes for it.
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2 (evt-1, evt-2; the malformed event unresolved)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	evt1ID := oktaNodeID("provisioning-event", "evt-1", "lifecycle")
	evt1, ok := byID[evt1ID]
	if !ok {
		t.Fatal("no evt-1 node")
	}
	if evt1.ControlFamily != "AC" || len(evt1.Controls) != 1 || evt1.Controls[0] != (ir.Control{Family: "AC", Base: 2, Enhancement: 4}) {
		t.Errorf("evt-1 control = %+v/%+v, want AC/AC-2(4)", evt1.ControlFamily, evt1.Controls)
	}
	if evt1.Kind != "okta_provisioning_event" {
		t.Errorf("evt-1.Kind = %q, want okta_provisioning_event", evt1.Kind)
	}
	wantAttrs := map[string]string{
		"event_type": "user.lifecycle.create",
		"outcome":    "SUCCESS",
		"actor_name": "Jane Admin",
		"target_ids": "user-1",
	}
	for k, want := range wantAttrs {
		if got := evt1.Attributes[k]; got != want {
			t.Errorf("evt-1 attribute %s = %q, want %q", k, got, want)
		}
	}
	if evt1.Provenance.Basis != "observed" {
		t.Errorf("evt-1 Provenance.Basis = %q, want observed", evt1.Provenance.Basis)
	}

	evt2ID := oktaNodeID("provisioning-event", "evt-2", "lifecycle")
	if _, ok := byID[evt2ID]; !ok {
		t.Fatal("no evt-2 node")
	}
}
