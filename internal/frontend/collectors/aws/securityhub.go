package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// SecurityHubCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const SecurityHubCollectorVersion = "aws-securityhub/v0.1.0"

// SecurityHubAPI names only the Security Hub operation this file's
// collector calls. See this package's doc.go for why this is a narrow,
// hand-written interface rather than the full *securityhub.Client
// (FR-3.10's fixture-based testing).
type SecurityHubAPI interface {
	DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

// notSubscribedMessage is the substring AWS's own documented behavior
// puts in an InvalidAccessException's message specifically when the
// account isn't subscribed to Security Hub in this Region ("Account
// <id> is not subscribed to AWS Security Hub") - confirmed against
// AWS's own error documentation, not guessed. InvalidAccessException is
// also returned for other causes (e.g. a member account querying before
// an organization admin relationship is fully established), so this
// collector matches on the message text, not just the exception type,
// before treating a DescribeHub failure as a confirmed absence rather
// than a real error - the same "check what the service actually
// documents this error shape to mean, don't assume every error of this
// type means the same thing" discipline docs/adr/0008 already applies
// to IAM's NoSuchEntity nuance.
const notSubscribedMessage = "is not subscribed to AWS Security Hub"

// Hub is one collected Security Hub subscription state - FR-3.6's
// enablement half for Security Hub specifically (findings - the
// aggregated security findings Security Hub actually surfaces - are a
// separate, larger data model this collector does not attempt yet, the
// same scoping GuardDuty and AWS Config's own enablement-first passes
// established).
//
// Present is a real, resolved measurement, not an absence: an account
// not subscribed to Security Hub in this Region is a definitive,
// confirmed fact (see notSubscribedMessage's own doc comment), the same
// confirmed-negative shape aws.Detector and aws.ConfigRecorder already
// establish for GuardDuty and AWS Config.
type Hub struct {
	Present            bool   `json:"present"`
	HubARN             string `json:"hub_arn,omitempty"`
	SubscribedAt       string `json:"subscribed_at,omitempty"`
	AutoEnableControls bool   `json:"auto_enable_controls"`

	Provenance provenance.Record `json:"provenance"`
}

// SecurityHubGraph is this account/Region's Security Hub enablement
// state. Hubs always has exactly one entry after a successful
// collection run - a synthetic Present:false entry when DescribeHub
// confirms the account isn't subscribed, per Hub's own doc comment.
type SecurityHubGraph struct {
	Hubs []Hub `json:"hubs"`
}

// CollectSecurityHub reads the account/Region's Security Hub
// subscription state - a single call, the same shape aws.CollectConfig
// uses (one API call returns everything this collector needs, no
// per-item fan-out).
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectSecurityHub(ctx context.Context, client SecurityHubAPI, observedAt time.Time) (*SecurityHubGraph, error) {
	out, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		var invalidAccess *types.InvalidAccessException
		if errors.As(err, &invalidAccess) && strings.Contains(valueOrEmpty(invalidAccess.Message), notSubscribedMessage) {
			return &SecurityHubGraph{Hubs: []Hub{{
				Present:    false,
				Provenance: securityHubRecord(observedAt),
			}}}, nil
		}
		return nil, fmt.Errorf("aws: securityhub: describe hub: %w", err)
	}

	return &SecurityHubGraph{Hubs: []Hub{{
		Present:            true,
		HubARN:             valueOrEmpty(out.HubArn),
		SubscribedAt:       valueOrEmpty(out.SubscribedAt),
		AutoEnableControls: out.AutoEnableControls != nil && *out.AutoEnableControls,
		Provenance:         securityHubRecord(observedAt),
	}}}, nil
}

// securityHubRecord is a thin wrapper around this package's shared
// observedRecord (provenance.go), fixing this file's own collector
// version - same pattern as configRecord/guardDutyRecord. There is no
// unresolved case for this collector: DescribeHub either succeeds, is
// confirmed not-subscribed (handled above, not an error case), or fails
// for a real reason CollectSecurityHub already surfaces as a hard
// error.
func securityHubRecord(observedAt time.Time) provenance.Record {
	return observedRecord(SecurityHubCollectorVersion, "securityhub:DescribeHub", map[string]string{}, observedAt)
}
