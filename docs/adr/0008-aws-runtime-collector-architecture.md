# ADR 0008: AWS runtime collector architecture, first collector: S3

Date: 2026-09-12
Status: Accepted

## Context

FR-3 (runtime collection, "the evidence-of-effectiveness half," IVV-CSO-SEE)
had no code at all before this ticket - `internal/frontend/collectors/aws`
and `.../okta` existed only as empty directories. Building the first real
collector meant deciding, for every future one, four things CLAUDE.md's
stack table doesn't already answer: which AWS SDK, how credentials are
obtained, how FR-3.10's "no live cloud dependency in unit tests" is
actually enforced rather than just asserted, and what a read-only IAM
policy document (FR-3.7) looks like in practice.

## Decision

**SDK: `aws-sdk-go-v2`.** Not named in CLAUDE.md's stack table, added
here as the only realistic choice for a Go AWS collector (actively
maintained, official, structured service clients). Flagging the addition
here rather than treating it as self-evidently pre-approved, per
CLAUDE.md's "every dependency is something a customer's security review
will ask about."

**Credentials: the SDK's own default chain, never handled by this
package.** Every collector function in `internal/frontend/collectors/aws`
takes an already-constructed client, never a region or credentials
value. Production code builds that client via
`config.LoadDefaultConfig(ctx)` against whatever read-only role or user
the customer has attached `docs/aws-readonly-policy.json` to. This
package doesn't construct, cache, or refresh credentials - "read-only
always" (CLAUDE.md) extends to "credential-handling is entirely the
customer's own AWS configuration," not something substrate manages.

**Testing (FR-3.10): a narrow, hand-written interface per service, not a
full-client mock.** `S3API` names exactly the four operations
`CollectS3` calls (`ListBuckets`, `GetBucketEncryption`,
`GetPublicAccessBlock`, `GetBucketLogging`). `*s3.Client` satisfies it
with zero adapter code (Go interface satisfaction is structural); tests
substitute `fakeS3`, which serves canned responses loaded from this
package's `testdata/*.json` fixtures. This was chosen over two
alternatives: (1) recording real HTTP wire traffic (a VCR/cassette-style
library) - rejected as a new test-only dependency for a problem the
interface boundary already solves for free, and (2) using the SDK's own
generated service mocks, if any - `aws-sdk-go-v2` doesn't generate them,
and a hand-written interface scoped to only the calls actually used is
more legible anyway (a reviewer can see the entire surface a collector
touches in one interface declaration).

**Read-only policy: incremental, scoped to what's actually implemented.**
`docs/aws-readonly-policy.json` today grants exactly the four S3 read
actions `CollectS3` calls - nothing anticipatory for IAM, CloudTrail,
KMS, VPC, or Config/GuardDuty/Security Hub, which don't have collectors
yet. Each future collector should add its own actions to this same
document in the same commit that adds the code needing them, so the
policy never grants more than the current binary can actually use.

**GovCloud (FR-3.8): no special-casing in the S3 collector itself.**
Every API call `CollectS3` makes is partition-generic; the SDK already
resolves them correctly once the caller's client is configured for a
GovCloud region. The one place partition awareness had to be a conscious
choice was the read-only policy's `Resource` ARNs, which use `arn:*:s3:::*`
(wildcarded partition segment) rather than hardcoding `arn:aws:s3:::*`, so
the same policy document works unmodified in both the standard and
GovCloud partitions.

**A discovered nuance, not a pre-planned one: `GetPublicAccessBlock`'s
"not found" is not "off."** S3's own documentation states the *effective*
Block Public Access posture is the most restrictive combination of a
bucket-level setting (what `GetPublicAccessBlock` returns) and a
separate, account-level setting (`s3control:GetPublicAccessBlock`, a
different API this collector does not call). A bucket with no
bucket-level configuration - which makes `GetPublicAccessBlock` error -
can still be fully locked down by the account-level setting. Treating
that error as "all four flags false" (the naive reading, and the same
mistake the Kubernetes NetworkPolicy and GitHub Actions permissions bugs
`/code-review` caught in the prior session shared: collapsing "we didn't
observe a value" into a default) would assert a specific negative
measurement this collector cannot actually back up. `collectBucketPublicAccessBlock`
records an Unresolved fact instead - the same "never guess" principle
FR-2.3 established for static parsing, now confirmed to generalize to a
live-API case nobody had reason to anticipate before implementing this
collector.

**Every field is a fact, resolved or not - never a bare `nil`.**
`Bucket.Encryption`/`PublicAccessBlock`/`Logging` are never nil pointers;
`CollectS3` always records something, with `Provenance.Confidence`
(`Deterministic` or `Unresolved`, plus `UnresolvedReason` in the latter
case) as the only signal for whether the value was actually resolved.
The first version of this file returned a bare `nil` for an unresolved
field - `/code-review` caught that this made a real API failure (a
missing IAM permission, throttling) byte-identical in the collected data
to a bucket nothing had ever asked about, which is exactly the "fail
silent" outcome `provenance.Record`'s own `Confidence`/`UnresolvedReason`
fields exist to rule out for every other collector in this codebase. The
Observed-vs-not distinction that `ir.go`'s mapping functions need (skip a
node when nothing was resolved) now reads `Provenance.Confidence !=
Deterministic` instead of a nil check - same mapping behavior, but the
raw `S3Graph` a caller gets back from `CollectS3` no longer discards the
failure itself.

**Buckets are collected concurrently, bounded to `maxConcurrentBuckets`
(16).** The three per-bucket API calls have no cross-bucket dependency,
so the original fully-sequential loop turned an account with hundreds of
buckets into hundreds of sequential round trips - real wall-clock cost
landing directly in a CI gate once this collector is wired into one.
`errgroup.Group.SetLimit` bounds concurrency without a per-account tuning
knob nobody would set correctly on a gate's first run. `listBucketNames`
still sorts before dispatch, so which goroutine handles which bucket
index is deterministic regardless of the API's own response order.

**`ir.go` maps only encryption and public access block, not logging - and
now shares the exact control values with Terraform, not just the same
literal.** `internal/frontend/terraform/ir.go` already carries a
human-reviewed mapping for the identical Declared measurements (SC-28(1)
for encryption, AC-3 for public access block, in
`mapEncryption`/`mapPublicAccessBlock`) - this collector's `ir.go` reuses
those exact control assignments for the Observed counterpart, which is
not a new compliance-content decision, just applying an already-approved
one to a second Basis. Both mappers now reference
`internal/frontend/controls.S3Encryption`/`S3PublicAccessBlock` rather
than each writing out `ir.Control{Family: "SC", Base: 28, Enhancement:
1}` as its own copy - `/code-review` flagged the duplicated literal as a
real risk (a future correction to one copy with no compiler-enforced link
to the other), not just a style nit, since these values are exactly the
kind of thing CLAUDE.md's compliance-content discipline requires explicit
review to change. Server access logging has no such precedent to reuse:
it belongs somewhere in the AU (Audit and Accountability) family, but
which specific control is a real judgment call nobody has reviewed yet.
`CollectS3` collects it (`Bucket.Logging`) and `ToIR` deliberately leaves
it unmapped, the same treatment an unmapped Terraform resource type gets
- collecting now and mapping later once reviewed costs nothing; guessing
the control today would not.

## Consequences

Positive. The interface-plus-fixture testing pattern and the
provenance/API-locator shape (`observedRecord`) are now proven end to end
and should carry to every future AWS collector (IAM, CloudTrail, KMS,
VPC, Config/GuardDuty/Security Hub) and to Okta with minimal new design
work - each is "another narrow interface, another fixture set, another
`ir.go` reusing or extending existing control assignments."

**Confirmed by collector two (IAM), added shortly after.** `IAMAPI` /
`CollectIAM` / `IAMToIR` needed no new architectural decisions: same
narrow interface, same `testdata/*.json` fixtures, same bounded
`errgroup` fan-out, same always-record-a-fact
(`Deterministic`/`Unresolved`) discipline, same incremental policy
additions to `docs/aws-readonly-policy.json`. Two things generalized out
of the duplication the second collector created: `observedRecord` /
`unresolvedRecord` moved to a shared `provenance.go` (each collector
keeps a thin wrapper fixing its own collector version and locator
parameter key), and node IDs now go through one `awsNodeID(service,
resource, aspect)` helper rather than a per-service `fmt.Sprintf`. Both
were flagged by `/code-review` as duplicated-literal risks of exactly
the kind `internal/frontend/controls` already exists to prevent.

The IAM collector also surfaced the mirror image of S3's
`GetPublicAccessBlock` nuance, worth recording because it cuts the other
way: `GetLoginProfile` returns a `NoSuchEntity` error for a user with no
console password, and that error IS a resolved "no" - AWS's own API
contract documents it to mean exactly that, with no second, uncollected
setting that could override it. So it is recorded as `Deterministic`,
not `Unresolved`. "An API error means unresolved" is therefore not a
rule this package can apply blindly; each error shape has to be checked
against what the service actually documents it to mean.

**Confirmed by collector three (CloudTrail, FR-3.2), added shortly
after.** Same narrow interface (`CloudTrailAPI`), same
`testdata/*.json` fixtures, same always-record-a-fact discipline. One
real shape difference from S3/IAM: `DescribeTrails` is a single
account/Region-wide call, not a per-item one, so `CollectCloudTrail`
only fans `collectConcurrent` out over the second call
(`GetTrailStatus`, one per trail) rather than every field like S3 and
IAM do.

A genuinely new nuance, not anticipated by either prior collector:
`DescribeTrails`' `IncludeShadowTrails` parameter defaults to `true`,
and at that default a multi-region trail (or an organization trail
replicated into a member account) comes back as an extra "shadow" row
for the current Region on top of its real one - which would have
produced two IR nodes with two different `awsNodeID` values for what is
actually one trail. `describeTrails` sets it to `false` explicitly.
This is the same class of bug S3's `GetPublicAccessBlock` nuance and
IAM's `NoSuchEntity` nuance already are - a live-API behavior neither
prior collector's design anticipated - but it would have produced
silently *duplicated*, not silently *missing or wrong*, evidence; worth
recording as its own variant of "the live API has a documented
behavior nobody had reason to check for until this specific collector."

CloudTrail is also this package's first control assignment with no
Terraform-side (Declared) counterpart to reuse from
`internal/frontend/controls` - `cloudTrailAuditRecordGeneration` (AU-12)
and `cloudTrailLogFileValidation` (AU-9), in `cloudtrail_ir.go`, are new
compliance content, not an Observed application of an already-reviewed
Declared mapping. Retention - the third concern FR-3.2 names alongside
configuration and log file integrity validation - is deliberately not
collected at all: it lives on the log destination (an S3 bucket's
lifecycle policy, or CloudWatch Logs' own retention setting), a
different collection surface than this collector's own trail-config and
trail-status calls, tracked as open follow-on work rather than guessed
at.

Negative. `docs/aws-readonly-policy.json` will need a statement added for
every future collector, in lockstep with the code - a process discipline,
not something enforced mechanically yet. Nothing checks today that the
policy document's actions actually match what the collectors in this
package call; that's worth a test if the list grows large enough to drift
silently.

Open. Server access logging's control mapping is unresolved, tracked
above, not decided here. Whether `CollectS3` should eventually also query
`s3control:GetPublicAccessBlock` (account-level Block Public Access) to
resolve today's `nil` result honestly is real follow-on work: right now
this collector can prove a bucket that HAS `RestrictPublicBuckets: true`
et al. set, but can never positively resolve one that relies entirely on
the account-level setting, which will show as `undetermined` all the way
through to a backend evaluation even though the bucket may in fact be
fully protected.

**Confirmed by collector four (security groups, FR-3.4's rule half),
added 2026-09-21.** Same narrow-interface pattern
(`SecurityGroupsAPI`), same `testdata/*.json` fixture testing. Two real
differences from every prior collector, not oversights:

1. **No per-item fan-out at all**, not even CloudTrail's partial one.
   `DescribeSecurityGroups` returns every rule for every security group
   inline in one paginated call - there is no second per-group API call
   this collector needs, so `collectConcurrent` isn't used here.
2. **A genuinely new shape: one collected fact is smaller than one API
   response entry, not bigger.** Every prior collector's fact granularity
   matched or was coarser than the API's own response shape (one
   `Bucket`, one `IAMUser`, one `Trail`). A security group's rule set
   nests CIDR ranges inside a permission (protocol + port range) inside
   the group; `flattenPermissions` explicitly un-nests this so each
   (security group, direction, protocol, port range, CIDR) combination
   is its own independently-provenanced `SecurityGroupRule` - the
   granularity a future "is 0.0.0.0/0 open on port 22" predicate needs
   to check directly, not reconstruct by re-grouping flattened rows back
   into AWS's original nested shape.

Deliberately scoped to IPv4 CIDR ranges only for this first pass - IPv6
ranges and cross-security-group references (`UserIdGroupPairs`) are
real rule sources this collector does not model at all yet, the same
"collect what's tractable now, defer the rest honestly" treatment
server access logging got above, not a completeness claim.

Mapped to SC-7(5) (Deny by Default - Allow by Exception): confirmed
against the vendored FedRAMP dataset (`KSI-CNA-RNT`, `KSI-CNA-MAT` both
cite `sc-7.5`) before proposing, the same dataset-first discipline the
Okta collectors' AC-2(4)/AC-6(5) mappings established
(`docs/adr/0015`). VPC/subnet topology (FR-3.4's other half - a graph,
not a flat rule list) is deliberately a separate follow-on collector,
not bundled here.

**Confirmed by collector five (subnets, FR-3.4's topology half),
added 2026-09-21 - the deferred half of collector four's own scoping
note above.** Same narrow-interface pattern (`SubnetsAPI`), same
no-fan-out single-paginated-call shape security groups established
(`DescribeSubnets` returns every attribute this collector needs
inline). Deliberately scoped to a subnet's own attributes only -
`CidrBlock`, `AvailabilityZone`, `VpcId`, `MapPublicIpOnLaunch` - not
the full "is this subnet actually public" determination, which needs a
Subnets -> RouteTables -> InternetGateways join (including AWS's
implicit main-route-table fallback for a subnet with no explicit
route table association). That join is real, disclosed follow-on work,
not attempted here; `MapPublicIpOnLaunch` alone is still a genuine,
independently meaningful SC-7 fact (governs whether a launched instance
gets a public IPv4 address at all, regardless of routing), so this
collector is honestly scoped rather than blocked on the harder problem.

Mapped to base SC-7 (Boundary Protection), not an enhancement - a
deliberate difference from security groups' SC-7(5): the dataset
citation check (`KSI-CNA-ULN`, `KSI-SVC-EIS` cite base `sc-7`; `sc-7.3`
Access Points has only one citation) confirmed base is both the
better-cited and the honest choice, since this collector's facts don't
yet support a more specific enhancement-level claim the way security
groups' deny-by-default rule set directly does.

**The deferred routing join, done same-session 2026-09-21.** Added
`DescribeRouteTables` to `SubnetsAPI` and the
Subnets -> RouteTables -> InternetGateways join the paragraph above
disclosed as not-yet-attempted: `resolveSubnetRouting` finds each
subnet's governing route table (its explicit association, or the VPC's
main route table if it has none - AWS's own documented fallback, not
this package's invention) and checks it for a route whose `GatewayId`
is prefixed `igw-`, recording the matched route's actual destination
CIDR rather than assuming `0.0.0.0/0`. Recorded as a second,
independently-provenanced fact (`SubnetRouting`, mapped to its own
`aws_subnet_routing` IR node) rather than added as fields on `Subnet`
directly - the same `Bucket.Encryption`/`PublicAccessBlock`/`Logging`
shape this file's own S3 section established, so a route table this
collector genuinely cannot resolve (no explicit association and no
main table found for the VPC at all - never actually produced by a
well-formed AWS account, but not assumed here) becomes an `Unresolved`
routing fact without touching the subnet's own already-resolved
CIDR/AZ/`MapPublicIpOnLaunch` node. Deliberately did not collapse an
unresolved join into `HasInternetGatewayRoute: false` - the same
"absence of evidence is not evidence of compliance" mistake `CollectS3`'s
`GetPublicAccessBlock` nuance already warns against in this file,
verified in this collector's own tests by breaking that exact path and
confirming it fails loudly.

Still mapped to base SC-7, not upgraded to SC-7(3) (Access Points) now
that routing resolves: SC-7(3) requires evidence that external network
connections are limited to a *managed, monitored* set, which one
subnet's own routing fact doesn't establish by itself - this session's
work is a richer measurement under the control already approved above,
not a new compliance-content decision requiring its own approval round.

**Confirmed by collector six (GuardDuty enablement, the first slice of
FR-3.6), added 2026-09-21.** FR-3.6 bundles three genuinely independent
AWS services (Config, GuardDuty, Security Hub - three separate SDKs,
three separate auth/API surfaces), a bigger step than any single-service
collector before it; sequenced the same one-thing-at-a-time way FR-3.4's
two halves were, starting with whichever sub-piece the vendored dataset
supports best. SI-4 (System Monitoring) had the highest total citation
count checked (base plus enhancements) of any FR-3.6 candidate, and
GuardDuty - a managed threat-detection service - is SI-4's most literal
match of the three services, so it went first; Config and Security Hub
are their own later passes, not bundled here.

Same list-then-per-item-detail shape `CollectCloudTrail` established
(`ListDetectors`, then `GetDetector` per ID) - GuardDuty's own
documented limit of at most one detector per account per Region means
this fan-out is normally trivial (zero or one item), but the shape is
kept consistent with every other multi-item collector in this package
rather than special-cased for "usually just one."

**A genuinely new nuance for this package: a successful list call
returning zero items is itself a resolved, meaningful fact, not
nothing to report.** Every prior collector's "list came back empty"
case was uninteresting (an account can have zero encrypted buckets and
that's just... zero relevant facts). GuardDuty is different: an account
where `ListDetectors` returns nothing has never had GuardDuty enabled
at all, which is exactly as real and reportable a fact as a detector
that exists and is `DISABLED` - collapsing it into silence (no node)
would repeat the same "absence of evidence is not evidence of
compliance" mistake `CollectS3`'s `GetPublicAccessBlock` nuance already
warns against, just at the account level instead of the per-resource
level. `CollectGuardDuty` returns an explicit `Present: false` fact for
this case rather than an empty slice, verified by a test that
deliberately reverts to the empty-slice version and confirms it fails.

Mapped to base SI-4, not SI-4(5) "System-Generated Alerts" even though
that enhancement is almost GuardDuty's literal job description: this
collector only resolves whether a detector exists and is on, not that
it is actually generating alerts (FR-3.6's separate, deferred findings
half) - the same "don't claim more than the collected fact supports"
discipline as security groups' SC-7(5) vs. subnets' base SC-7 split.
