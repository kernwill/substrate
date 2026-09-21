package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OktaAPI names the Okta Management API calls this package's collectors
// make. Every collector here is defined against this interface, never a
// concrete client - the same narrow-interface, fixture-testable pattern
// aws.S3API/IAMAPI/CloudTrailAPI use, adapted for a hand-rolled REST
// client rather than a vendor SDK (docs/adr/0015).
//
// ListPolicies covers every Okta policy-backed FR-3.9 surface this
// package collects: MFA enrollment (mfa.go) today, and session policy
// and admin role assignment policies share the same
// GET /api/v1/policies resource, distinguished only by policyType - one
// real Okta API operation reused across collectors, not an artificial
// merge of unrelated ones.
//
// ListPolicyRules is the second call session-policy collection needs
// (sessionpolicy.go): unlike MFA_ENROLL, an OKTA_SIGN_ON policy's actual
// idle-timeout/session-lifetime values live on its rules
// (GET /api/v1/policies/{id}/rules), not on the policy object itself -
// a real shape difference from MFA_ENROLL, not an oversight, the same
// kind of "the live API has a documented behavior nobody had reason to
// check for until this specific collector" docs/adr/0008 already
// records for S3/IAM/CloudTrail.
// ListSystemLogEvents is the third operation this interface names, for
// provisioning.go's provisioning/deprovisioning event collection - an
// entirely different Okta resource (the System Log, an audit event
// stream) from the policy-backed calls above, closer in shape to
// aws.CloudTrailAPI's live-status read than to anything else in this
// package.
type OktaAPI interface {
	ListPolicies(ctx context.Context, policyType string) ([]RawPolicy, error)
	ListPolicyRules(ctx context.Context, policyID string) ([]RawPolicyRule, error)
	ListSystemLogEvents(ctx context.Context, since, until time.Time, eventTypes []string) ([]RawLogEvent, error)
}

// RawPolicy is one policy object exactly as Okta's Management API
// returns it, before any collector-specific interpretation of
// Settings. Each collector unmarshals Settings into its own typed
// shape, since what it means varies entirely by policy type (an
// MFA_ENROLL policy's settings and an OKTA_SIGN_ON policy's settings
// share no fields).
type RawPolicy struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Priority   int             `json:"priority"`
	Conditions RawConditions   `json:"conditions"`
	Settings   json.RawMessage `json:"settings"`
}

// RawConditions is the subset of a policy's conditions object this
// package models: which groups it applies to. Okta's conditions object
// carries other condition types (network, people.users, and others);
// unmodeled ones are simply not decoded, not an error - encoding/json
// ignores object fields with no matching struct field.
type RawConditions struct {
	People RawPeopleCondition `json:"people"`
}

type RawPeopleCondition struct {
	Groups RawGroupCondition `json:"groups"`
}

type RawGroupCondition struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// RawPolicyRule is one rule object exactly as Okta's Management API
// returns it (GET /api/v1/policies/{id}/rules), before any
// collector-specific interpretation of Actions - the rule-level
// counterpart to RawPolicy.Settings.
type RawPolicyRule struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Status   string          `json:"status"`
	Priority int             `json:"priority"`
	Actions  json.RawMessage `json:"actions"`
}

// RawLogEvent is one event exactly as Okta's System Log API returns it
// (GET /api/v1/logs), the subset of fields provisioning.go needs -
// which account, which lifecycle transition, when, by whom, and whether
// it succeeded.
type RawLogEvent struct {
	UUID      string        `json:"uuid"`
	Published time.Time     `json:"published"`
	EventType string        `json:"eventType"`
	Outcome   RawLogOutcome `json:"outcome"`
	Actor     RawLogActor   `json:"actor"`
	Target    []RawLogActor `json:"target"`
}

type RawLogOutcome struct {
	Result string `json:"result"`
	Reason string `json:"reason"`
}

// RawLogActor is used for both an event's actor (who performed it) and
// its targets (what it was performed on) - Okta's System Log schema
// gives both the same id/type/displayName shape.
type RawLogActor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"displayName"`
}

// RESTClient is OktaAPI's production implementation: authenticated GET
// requests against one customer Okta org, using tokens minted by a
// TokenSource (auth.go). Production wiring code owns constructing this;
// collectors in this package only ever see it through the OktaAPI
// interface, never this concrete type.
type RESTClient struct {
	orgURL string
	tokens *TokenSource
	http   httpDoer
}

// NewRESTClient builds a RESTClient against orgURL (e.g.
// "https://example.okta.com", no trailing slash required), authorizing
// every request with an access token from tokens. httpClient defaults
// to http.DefaultClient if nil - the same "transport plumbing, not
// credential material" default TokenSource's own HTTPClient field
// documents.
func NewRESTClient(orgURL string, tokens *TokenSource, httpClient httpDoer) *RESTClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RESTClient{orgURL: strings.TrimRight(orgURL, "/"), tokens: tokens, http: httpClient}
}

// ListPolicies calls GET /api/v1/policies?type=policyType, a single
// org-wide call - no per-item fan-out, the same shape
// aws.describeTrails uses for CloudTrail (docs/adr/0008's "confirmed by
// collector three" section) rather than S3/IAM's per-bucket/per-user
// pattern.
//
// Okta paginates this endpoint past a page-size threshold via a Link
// response header; that is not handled here yet, since no customer
// fixture or self-test org has exercised it - a real gap, not an
// oversight, worth a fixture-backed test the first time it's addressed
// rather than guessed at now.
func (c *RESTClient) ListPolicies(ctx context.Context, policyType string) ([]RawPolicy, error) {
	reqURL := fmt.Sprintf("%s/api/v1/policies?type=%s", c.orgURL, url.QueryEscape(policyType))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("okta: building ListPolicies request: %w", err)
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: getting access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta: ListPolicies(%s) request: %w", policyType, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta: ListPolicies(%s) returned status %d", policyType, resp.StatusCode)
	}

	var policies []RawPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, fmt.Errorf("okta: decoding ListPolicies(%s) response: %w", policyType, err)
	}
	return policies, nil
}

// ListPolicyRules calls GET /api/v1/policies/{policyID}/rules, one call
// per policy - session-policy collection's per-item fan-out, the same
// shape aws.CollectS3/CollectIAM use for buckets/users. Okta orgs
// typically have a handful of sign-on policies (not hundreds), so this
// package does not bound-concurrency this fan-out the way
// aws.collectConcurrent does for potentially large AWS resource counts;
// worth revisiting if a real customer org's policy count ever makes
// that assumption wrong.
func (c *RESTClient) ListPolicyRules(ctx context.Context, policyID string) ([]RawPolicyRule, error) {
	reqURL := fmt.Sprintf("%s/api/v1/policies/%s/rules", c.orgURL, url.PathEscape(policyID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("okta: building ListPolicyRules request: %w", err)
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: getting access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta: ListPolicyRules(%s) request: %w", policyID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta: ListPolicyRules(%s) returned status %d", policyID, resp.StatusCode)
	}

	var rules []RawPolicyRule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		return nil, fmt.Errorf("okta: decoding ListPolicyRules(%s) response: %w", policyID, err)
	}
	return rules, nil
}

// ListSystemLogEvents calls GET /api/v1/logs, filtered to eventTypes and
// bounded to [since, until). Like ListPolicies, this does not follow the
// response's Link-header pagination - a real gap for a since/until
// window wide enough to exceed one page, flagged here rather than
// silently truncating results; worth a fixture-backed test the first
// time a real customer window is known to exceed it.
func (c *RESTClient) ListSystemLogEvents(ctx context.Context, since, until time.Time, eventTypes []string) ([]RawLogEvent, error) {
	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("until", until.UTC().Format(time.RFC3339))
	if len(eventTypes) > 0 {
		clauses := make([]string, len(eventTypes))
		for i, et := range eventTypes {
			clauses[i] = fmt.Sprintf(`eventType eq %q`, et)
		}
		q.Set("filter", strings.Join(clauses, " or "))
	}

	reqURL := fmt.Sprintf("%s/api/v1/logs?%s", c.orgURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("okta: building ListSystemLogEvents request: %w", err)
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("okta: getting access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("okta: ListSystemLogEvents request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("okta: ListSystemLogEvents returned status %d", resp.StatusCode)
	}

	var events []RawLogEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, fmt.Errorf("okta: decoding ListSystemLogEvents response: %w", err)
	}
	return events, nil
}
