// Package okta collects live Okta org state (FR-3.9: MFA enforcement,
// session policy, provisioning and deprovisioning events, admin role
// assignments) - the Observed counterpart to internal/frontend's static,
// Declared parsers, and this project's second FR-3 source after AWS.
//
// # Authentication
//
// Unlike AWS (internal/frontend/collectors/aws), Okta has no default
// credential chain to pick up ambiently. Every collector in this package
// takes an already-authenticated OktaAPI, never a client ID, org URL, or
// private key itself. Production callers construct that client's
// underlying token source from an OAuth 2.0 private-key-JWT exchange
// against a customer-provisioned Okta API Services app - see
// docs/adr/0015 for why that model was chosen over an SSWS admin token
// or an OAuth client secret, and docs/okta-api-scopes.md (added
// alongside the first real collection call) for the exact, minimal scope
// list this package's collectors need. This package never provisions the
// API Services app, registers the signing key, or manages key rotation;
// that is entirely the customer's setup step.
//
// # Testing (FR-3.10)
//
// Every collector is defined against a narrow, hand-written Go interface
// naming only the specific REST calls it makes (OktaAPI), never a
// generic HTTP client. Tests substitute a fake implementation that
// serves canned responses loaded from this package's testdata fixtures.
// No collector or its tests ever makes a live Okta call.
//
// See docs/adr/0015 for the full reasoning behind this shape.
package okta
