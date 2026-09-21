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
| Admin role assignments (`adminrole.go`) | `GET /api/v1/users`, `GET /api/v1/users/{id}/roles` | `okta.users.read` |

Combined scope list for an API Services app running all four collectors:

```
okta.policies.read
okta.logs.read
okta.users.read
```

## Unverified

The exact scope name for `GET /api/v1/users/{id}/roles` specifically
(as opposed to the base `/api/v1/users` read) has not been confirmed
against a live Okta org or Okta's current scope reference - `okta.users.read`
is believed correct (role assignment is nested under the Users API
namespace) but not yet exercised end to end. Confirm against a real org
before relying on this table for a customer's actual app provisioning,
the same "not yet exercised by any fixture or self-test org" caveat
`client.go`'s pagination comments already carry for these same endpoints.
