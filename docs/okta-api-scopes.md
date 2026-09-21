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
check the live dashboard/docs" discipline. Still not exercised against a
live org or self-test fixture end to end - the scope *name* is now
verified from the docs, but a real API Services app has never actually
been granted it and made a real call, which is a different kind of
verification.

Combined scope list for an API Services app running all four collectors:

```
okta.policies.read
okta.logs.read
okta.users.read
okta.roles.read
```
