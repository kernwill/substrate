package okta

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/kernwill/substrate/internal/provenance"
)

// ProvisioningCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const ProvisioningCollectorVersion = "okta-provisioning/v0.1.0"

// provisioningEventTypes are the Okta System Log eventType values
// FR-3.9's "provisioning and deprovisioning events" collects: account
// lifecycle state transitions only, not every user-related event Okta
// logs. Profile updates, group membership changes, and application
// assignment events are a different, broader surface this collector
// deliberately does not touch - scoped the same way IAMUser's own doc
// comment scopes AWS IAM to users/MFA/access-key-age rather than roles
// and policies.
var provisioningEventTypes = []string{
	"user.lifecycle.create",
	"user.lifecycle.activate",
	"user.lifecycle.deactivate",
	"user.lifecycle.suspend",
	"user.lifecycle.unsuspend",
}

// ProvisioningEvent is one collected Okta account lifecycle event.
// TargetIDs/TargetDisplayNames are never nil when Provenance.Confidence
// is Deterministic, even for an event with exactly one target - see
// aws.Bucket's doc comment for why this package always records a fact,
// resolved or not, rather than dropping one it couldn't fully parse.
type ProvisioningEvent struct {
	ID            string   `json:"id"`
	EventType     string   `json:"event_type"`
	Published     string   `json:"published"`
	Outcome       string   `json:"outcome"`
	OutcomeReason string   `json:"outcome_reason,omitempty"`
	ActorID       string   `json:"actor_id"`
	ActorName     string   `json:"actor_name"`
	TargetIDs     []string `json:"target_ids"`
	TargetNames   []string `json:"target_names"`

	Provenance provenance.Record `json:"provenance"`
}

// ProvisioningEventGraph is every account lifecycle event found in the
// caller's Okta org within the requested window.
type ProvisioningEventGraph struct {
	Events []ProvisioningEvent `json:"events"`
}

// CollectProvisioningEvents fetches every account lifecycle event
// published in [since, until) from the caller's Okta org - a single
// call (client.ListSystemLogEvents), then validates each returned event
// independently so one malformed entry doesn't take down the whole
// collection run.
//
// since and until are supplied by the caller, not computed here: this
// package never tracks "time since last collection run" state itself,
// the same "credential-handling is entirely the caller's responsibility"
// principle docs/adr/0015 established for authentication, applied here
// to the collection window instead. Production wiring code (substrate
// collect) owns deciding what window a given run should request.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// distinct from Published (when the lifecycle event itself occurred) -
// matching every other collector in this codebase's convention of never
// calling time.Now() itself (FR-5.3).
func CollectProvisioningEvents(ctx context.Context, client OktaAPI, observedAt, since, until time.Time) (*ProvisioningEventGraph, error) {
	raw, err := client.ListSystemLogEvents(ctx, since, until, provisioningEventTypes)
	if err != nil {
		return nil, fmt.Errorf("okta: provisioning: list system log events: %w", err)
	}

	events := make([]ProvisioningEvent, 0, len(raw))
	for _, e := range raw {
		events = append(events, parseProvisioningEvent(e, observedAt))
	}
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })

	return &ProvisioningEventGraph{Events: events}, nil
}

func parseProvisioningEvent(e RawLogEvent, observedAt time.Time) ProvisioningEvent {
	const api = "okta:ListSystemLogEvents"
	base := ProvisioningEvent{ID: e.UUID, EventType: e.EventType}

	if e.UUID == "" || e.EventType == "" || e.Published.IsZero() {
		base.Provenance = provisioningUnresolvedRecord(e.UUID, api, "system log event missing uuid, eventType, or published timestamp", observedAt)
		return base
	}

	base.Published = e.Published.UTC().Format(time.RFC3339)
	base.Outcome = e.Outcome.Result
	base.OutcomeReason = e.Outcome.Reason
	base.ActorID = e.Actor.ID
	base.ActorName = e.Actor.DisplayName

	targetIDs := make([]string, len(e.Target))
	targetNames := make([]string, len(e.Target))
	for i, t := range e.Target {
		targetIDs[i] = t.ID
		targetNames[i] = t.DisplayName
	}
	base.TargetIDs = targetIDs
	base.TargetNames = targetNames

	base.Provenance = provisioningRecord(e.UUID, api, observedAt)
	return base
}

// provisioningRecord and provisioningUnresolvedRecord are thin wrappers
// around this package's shared observedRecord/unresolvedRecord
// (provenance.go), fixing this file's own collector version - same
// pattern as mfaRecord/mfaUnresolvedRecord (mfa.go). eventID may be
// empty for an event this collector couldn't even identify (no uuid at
// all); the locator still carries whatever was available.
func provisioningRecord(eventID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(ProvisioningCollectorVersion, api, map[string]string{"event_id": eventID}, observedAt)
}

func provisioningUnresolvedRecord(eventID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(ProvisioningCollectorVersion, api, reason, map[string]string{"event_id": eventID}, observedAt)
}
