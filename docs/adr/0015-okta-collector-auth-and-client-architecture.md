# ADR 0015: Okta collector authentication and client architecture

Date: 2026-09-20
Status: Accepted

## Context

FR-3.9 (Okta: MFA enforcement, session policy, provisioning and
deprovisioning events, admin role assignments) is the next collector after
Dockerfile (`docs/adr/0014`), per the sequencing recorded when that work was
agreed. `internal/frontend/collectors/okta` exists only as an empty
directory - no code, no decisions, nothing to build on.

Unlike AWS (`docs/adr/0008`), Okta has no equivalent of an SDK default
credential chain resolved against an instance role. There is no ambient
credential this collector can simply pick up; how substrate authenticates to
a customer's Okta org is itself the first design question, and it has no
precedent elsewhere in this codebase.

Two decisions were needed before any collection code could be written:
which Okta auth model to use, and whether to pull in an SDK or build the
client by hand.

## Decision

**Auth: OAuth 2.0 via an Okta API Services app, authenticated with a
private-key JWT client assertion.** Not an SSWS token from a dedicated
admin user. Three reasons, in order of weight:

1. **Scoping.** An API Services app grants exactly the OAuth scopes it's
   configured with (`okta.users.read`, `okta.logs.read`, and equivalents for
   session policy and role assignment reads). An SSWS token inherits
   whatever permissions the admin user it's minted from happens to have -
   there is no finer-grained scope to request. This is the same "grant
   nothing beyond what's implemented" discipline `docs/aws-readonly-policy.json`
   already enforces for AWS; an API Services app is the Okta object that
   makes the equivalent statement expressible at all.
2. **No shared secret to leak.** A private key never leaves the customer's
   possession or transits the network - substrate is handed a public key to
   register, and signs a JWT assertion locally with the private half.
   Compare an SSWS token or an OAuth client secret, either of which is a
   bearer credential that grants access to whoever holds it, full stop, and
   that this collector would need to receive from the customer directly.
3. **Not tied to a human-shaped account.** An API Services app is a
   first-class Okta application object, not an admin user with a token
   minted against it. It survives an employee offboarding, doesn't compete
   with a real person's own SSWS token limit, and doesn't silently expire
   after 30 days of inactivity the way an SSWS token does - a real
   operational risk for a collector a CI gate might invoke on a cadence
   longer than that.

Credential-handling itself stays "entirely the customer's own
configuration," matching AWS's precedent: this package takes an
already-constructed, already-authenticated client. It does not provision
the API Services app, register the key, or manage key rotation - that is
the customer's setup step, to be documented the same way
`docs/aws-readonly-policy.json` documents AWS's read-only role
(`docs/okta-api-scopes.md`, added in the same commit as the first real
Okta collection call).

**Client: hand-rolled, `net/http` plus stdlib `crypto/rsa` - no new SDK
dependency.** The private-key-JWT token exchange is a bounded, well-specified
piece of work (build a claims object, sign it RS256, POST it to Okta's
token endpoint, cache the resulting bearer token for its lifetime) that
stdlib `crypto/rsa` and `encoding/json` handle without help. The
collection calls themselves are plain JSON GETs against Okta's REST API,
the same shape `IAMAPI`/`S3API`/`CloudTrailAPI` already narrow AWS's SDK
down to. Pulling in `okta-sdk-golang` would mean the first non-AWS,
non-HCL, non-OPA SDK dependency in the project, and CLAUDE.md's "every
dependency is something a customer's security review will ask about" sets
a real bar against that for a job stdlib already covers. It also isn't
obvious the official SDK's own client types satisfy this package's
narrow-hand-written-interface testing pattern (FR-3.10) as cleanly as a
raw `*http.Client` does - a bespoke `OktaAPI` interface naming exactly the
four calls this collector makes gets the same fixture-based test story
`aws.S3API` already proved out, with zero adapter code.

## Consequences

Positive. No new dependency, no new SBOM line, matches the existing
narrow-interface-per-service pattern exactly, and the credential model is
strictly better-scoped than AWS's (a fine-grained OAuth scope list vs. an
IAM policy document, but the same "customer attaches least privilege,
substrate never manages the credential" shape).

Negative, disclosed rather than deferred. Hand-rolling the token exchange
means this package owns something AWS's collector never had to: token
lifetime tracking and refresh-before-expiry logic. `aws-sdk-go-v2`'s
credential chain does this invisibly for the AWS collectors; this
package's Okta client needs its own (small, but real) cached-token-plus-
expiry-check code path, to be covered by its own fixture-based test rather
than assumed correct by analogy to AWS.

Open. The exact OAuth scope list per REST call, and the JWT claims Okta's
token endpoint requires (`iss`/`sub` both set to the client ID, `aud` set
to the org's token endpoint, a short `exp`), are implementation detail for
the first collection call, not decided here. Which control(s) MFA
enforcement, session policy, provisioning/deprovisioning events, and admin
role assignments map to is new compliance content - like CloudTrail's
AU-9/AU-12 (`docs/adr/0008`) with no Declared-side mapping to reuse - and
per CLAUDE.md's compliance-content review discipline, will be proposed for
explicit approval separately from this architecture decision, before any
Rego or `ir.go` mapping is written.
