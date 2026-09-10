# ADR 0005: Class A self-certification subject is the eventual hosted control plane

Date: 2026-09-10
Status: Accepted

## Context

REQUIREMENTS.md section 16.4 requires deciding what the company itself
certifies under FedRAMP 20x Class A, and section 31's "Open decisions"
list already carries a standing recommendation ("the eventual hosted
control plane, with Phase 0 only starting the SOC 2 clock") without ever
resolving it into a committed decision the way backend one/two and the
CLI-first deployment model were resolved. T-015's own done criterion is
an ADR recording the decision and reasoning - this one has never been
written, which is why the recommendation has sat as "open" rather than
"resolved" since the requirements document was first drafted.

Class A is FedRAMP 20x's new pilot certification tier: no sponsor
required, independent assessment optional rather than mandatory (section
5's certification-class table). It replaces nothing - it's new pilot
scope, aimed at commercial-motion certification without a government
sponsor.

The question this ADR answers is narrower than "should we pursue Class A
at all" (that depends on T-011's and T-013's findings - whether the
minimum bar is achievable and whether it confers real agency purchasing
legitimacy, both still open). It answers: if we do, what is "we"? What
service or entity actually undergoes assessment?

Two candidate subjects were on the table:

1. **The eventual hosted control plane** (Phase 3, FR-10) - the
   multi-tenant findings-ingestion and dashboard service that receives
   normalized findings pushed by the CLI, per section 19's architecture
   constraint (never credentials, never raw source, never collection on
   our own infrastructure).
2. **A minimal or hollow entity created solely to hold a Class A badge**
   ahead of having a real hosted service - e.g. some thin wrapper stood
   up earlier than Phase 3 specifically to get through assessment sooner.

## Decision

Certify the hosted control plane, once it exists (Phase 3, year two at
the earliest per the phase roadmap). Do not stand up any earlier or
thinner subject to accelerate self-certification.

Reasoning, beyond what section 16.4 already states ("certifying a hollow
service to hold a badge will not survive assessor contact"):

FedRAMP 20x's certification model targets a Cloud Service Offering.
Nothing before Phase 3 is a CSO in the sense the framework assesses.
NFR-4 requires read-only access to customer systems with no hosted
collection; the CLI and its collectors run in the customer's own CI, not
ours. There is no multi-tenant boundary, no customer data at rest under
our control, and no operational surface for an assessor to test against
before the hosted plane exists - a CLI binary is not a service any
assessor's methodology is built to evaluate. Certifying anything earlier
would mean assessing a shape of thing 20x wasn't designed to certify, on
top of the credibility problem section 16.4 already names directly.

This does not block or delay anything else. SOC 2 Type II (T-012) starts
now regardless, independent of this decision, per section 16.4's own
instruction and because it is this plan's longest lead-time item either
way.

## Consequences

Positive. When self-certification happens, it happens against something
with a real customer-facing risk surface - exactly the kind of proof a
prospect or an assessor would find credible, and the kind of dogfooding
that supports the "neutral tool every assessor likes" positioning in
section 31's open decision 7.

Negative. Self-certification is not available as a credibility signal
during Phase 1 or Phase 2 sales conversations - there is no Class A badge
to point to until year two at the earliest. During that window, product
credibility has to rest on the Phase 1 exit criterion instead: a
FedRAMP-recognized assessor reviewing real output and stating in writing
what they would and would not accept.

Unproven. Whether pursuing Class A self-certification is worth doing at
all remains open regardless of this decision - it depends on T-011's
finding (can the minimum bar actually be met) and T-013's discovery
question (does Class A confer real agency purchasing legitimacy, per
section 16.4's "five conversations"). This ADR settles the subject
question conditional on going forward, not whether to go forward.
