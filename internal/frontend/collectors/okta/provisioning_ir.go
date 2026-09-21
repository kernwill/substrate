package okta

import (
	"strings"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// provisioningAutomatedAuditActions is the control assignment for an
// Okta account lifecycle event: AC-2(4) (Automated Audit Actions), not
// the base control. Unlike the MFA and session-policy mappings in this
// package, choosing the enhancement here is not a guess about something
// this collector can't resolve (compare mfaEnrollmentIA2's deliberate
// avoidance of IA-2(1)/(2)) - AC-2(4)'s own definition is "automatically
// audit account creation, modification, enabling, disabling, and
// removal actions," and a queryable System Log event IS that automated
// audit record, not a proxy for it. Confirmed against the vendored
// FedRAMP dataset (internal/rules/data/fedramp-consolidated-rules.json):
// ac-2.4 is cited by KSI-MLA-LET, KSI-MLA-RVL, and KSI-SVC-ACM. Proposed
// and approved 2026-09-21 alongside this collector's first
// implementation.
var provisioningAutomatedAuditActions = ir.Control{Family: "AC", Base: 2, Enhancement: 4}

// ProvisioningEventsToIR converts g's events into IR nodes, one per
// resolved event. An event this collector could not validate
// (Provenance.Confidence != Deterministic) produces no node - the same
// "never guess" treatment every other mapper in this codebase applies.
func ProvisioningEventsToIR(g *ProvisioningEventGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, e := range g.Events {
		if node, ok := mapProvisioningEvent(e); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapProvisioningEvent records e verbatim as raw attributes (FR-5.9:
// this mapper records that a lifecycle event of a given type occurred,
// with what outcome, never whether the surrounding process around it
// was adequate - that judgment belongs in a backend predicate).
// TargetIDs/TargetNames are comma-joined into single attributes rather
// than modeled as separate nodes: an ir.Node's Attributes is a flat
// string map (node.go), and a lifecycle event's target list is
// small and fixed in practice (the account the event acted on, almost
// always exactly one), not the kind of unbounded collection a separate
// per-target node would be worth the complexity for.
func mapProvisioningEvent(e ProvisioningEvent) (ir.Node, bool) {
	if e.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	return ir.Node{
		ID:            oktaNodeID("provisioning-event", e.ID, "lifecycle"),
		ControlFamily: provisioningAutomatedAuditActions.Family,
		Controls:      []ir.Control{provisioningAutomatedAuditActions},
		Kind:          "okta_provisioning_event",
		Attributes: map[string]string{
			"event_type":     e.EventType,
			"published":      e.Published,
			"outcome":        e.Outcome,
			"outcome_reason": e.OutcomeReason,
			"actor_id":       e.ActorID,
			"actor_name":     e.ActorName,
			"target_ids":     strings.Join(e.TargetIDs, ","),
			"target_names":   strings.Join(e.TargetNames, ","),
		},
		Provenance:    e.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
