# Okta API Services app - required OAuth scopes

The customer-provisioned Okta API Services app substrate's Okta collectors
authenticate as (`docs/adr/0015`'s private-key-JWT model) needs exactly the
scopes below - nothing more. This is Okta's equivalent of
`docs/aws-readonly-policy.json`: incremental, scoped to what's actually
implemented, updated in the same commit as the collector that needs a new
scope, never granted ahead of the code that uses it.

This file should have been added in the commit that added the first real
Okta collection call (`mfa.go`, per `docs/adr/0015`'s own text) and was not -
added here after the fact, covering all four FR-3.9 collectors built in that
session rather than incrementally. Treat the gap as closed as of this
commit, not as a precedent for skipping it next time.

| Collector | Okta API call(s) | Required scope |
|---|---|---|
| MFA enrollment (`mfa.go`) | `GET /api/v1/policies?type=MFA_ENROLL` | `okta.policies.read` |
| Session policy (`sessionpolicy.go`) | `GET /api/v1/policies?type=OKTA_SIGN_ON`, `GET /api/v1/policies/{id}/rules` | `okta.policies.read` |
| Provisioning/deprovisioning events (`provisioning.go`) | `GET /api/v1/logs` | `okta.logs.read` |
| Admin role assignments (`adminrole.go`) | `GET /api/v1/users` | `okta.users.read` |
| Admin role assignments (`adminrole.go`) | `GET /api/v1/users/{id}/roles` | `okta.roles.read` |

`GET /api/v1/users/{id}/roles` needs its own scope, `okta.roles.read`, not
`okta.users.read` - confirmed 2026-09-21 against Okta's own OAuth 2.0 scope
reference (https://developer.okta.com/docs/api/oauth2/), which describes
`okta.roles.read` as covering read access to a user's administrative role
assignments. This was the wrong initial guess in this file's first version
(reasoned from "role assignment is nested under the Users API namespace,"
which turned out not to be how Okta scopes this operation) - resolved by
checking the actual reference doc rather than left as a standing
assumption, per this project's "don't reason from stale assumptions...
check the live dashboard/docs" discipline.

Combined scope list for an API Services app running all four collectors:

```
okta.policies.read
okta.logs.read
okta.users.read
okta.roles.read
```

## Two more setup steps, beyond scopes - confirmed 2026-09-21 against a real org

Verified end to end against a live Okta Integrator Free Plan org
(`/Users/willkern/substrate-self-test/SUBSTRATE-TESTING.md`'s own section 6).
Two things blocked a working connection that this file didn't originally
mention, neither of them a scope problem:

1. **DPoP.** A fresh API Services app on the Integrator Free Plan enforces
   "Require Demonstrating Proof of Possession (DPoP) header in token
   requests" by default. `TokenSource` (auth.go) does not implement DPoP -
   it mints a plain bearer-token client-credentials request per
   docs/adr/0015, nothing more. Against a DPoP-enforcing app this fails at
   the token endpoint with `invalid_dpop_proof: The DPoP proof JWT header
   is missing`, before any scope or role question is even reached. Today's
   fix is operational: turn the app's **Proof of possession** toggle off
   (app's General tab). Real follow-on work, not done here: DPoP is
   Okta's recommended posture going forward, so `TokenSource` should
   probably support it for real rather than assume every customer org has
   it disabled - tracked as open work, not solved by this note.
2. **Admin role assignment is a second, separate authorization layer from
   OAuth scopes.** Granting all four scopes above is necessary but not
   sufficient - the access token will correctly carry every granted scope
   (confirmed by decoding a real token's `scp` claim), and `/api/v1/users`
   will work, but `/api/v1/policies` and `/api/v1/logs` still return
   `403 E0000006: You do not have permission to perform the requested
   action` until the app itself is ALSO assigned an actual Okta admin
   role, on the app's own **Admin roles** tab (Edit assignments). OAuth
   scopes gate which endpoints a request is even allowed to target; the
   assigned admin role gates what it's actually permitted to do once
   there - two independent checks, both required. **Read-Only
   Administrator** is the correct least-privilege choice: it can read
   policies, logs, users, and roles without being able to modify
   anything, matching this project's "read-only always" principle
   exactly (the same discipline `docs/aws-readonly-policy.json` enforces
   for the AWS collectors). Confirmed via Okta's own support docs
   (https://support.okta.com/help/s/article/receiving-error-code-e0000006-when-calling-okta-management-api-despite-having-correct-scopes),
   not guessed.
