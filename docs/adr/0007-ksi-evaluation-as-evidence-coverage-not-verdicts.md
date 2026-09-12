# ADR 0007: KSI evaluation starts as evidence-coverage checking, not pass/fail judgment

Date: 2026-09-10
Status: Accepted

## Context

FR-6.1 requires "mapping from IR nodes to FRR rules and KSIs, expressed in
Rego, one module per KSI family with tests" - the first piece of the
FedRAMP 20x backend, and the first thing in this codebase allowed to know
what a KSI is.

Two facts about the current state of the project shaped this decision:

1. **Coverage is nowhere near complete.** Every KSI indicator in the
   vendored dataset references a broad set of NIST 800-53 controls (e.g.
   `KSI-IAM-JIT` references 30). Today's three frontend collectors
   (Terraform, Kubernetes, GitHub Actions) produce IR nodes for exactly
   seven distinct controls total. No indicator's full control list is
   covered by any real collector yet, and won't be for a long time -
   collectors get added one at a time, same as `FR-2.1`, `FR-2.4/2.5`,
   and `FR-2.6` landed one commit each.
2. **The frontend mapping packages already draw a line this backend must
   respect.** `internal/frontend/terraform/ir.go`, `.../kubernetes/ir.go`,
   and `.../githubactions/ir.go` all state the same principle in their own
   doc comments: a mapping function decides *which* control a fact is
   about, never whether the fact's value represents good or bad security
   posture (FR-5.9). That judgment was left, deliberately, for "a backend
   predicate" to make later. This ticket is that later.

Given both, writing real satisfied/not_satisfied logic for every
KSI-SVC-* indicator this session would require authoring a per-control-
type predicate (e.g. "an `s3_bucket_public_access_block` node's four
attribute values must all be `true`") for controls this backend has never
looked at the evidence shape of before, under review pressure to ship
something. That is exactly the kind of unreviewed compliance-content
guess `CLAUDE.md`'s "an invented interpretation... becomes an incorrect
attestation" line and `[[Compliance content review]]` (assistant memory)
exist to prevent.

## Decision

`rego/ksi/svc/svc.rego` - the first, and so far only, family module -
computes indicator status from **evidence coverage alone**: does the
graph contain at least one node naming each control the indicator
references. It never inspects a node's `Attributes` to judge whether the
collected value is actually good.

Concretely, four outcomes, one per indicator:

- **`satisfied`**: every referenced control has at least one node naming
  it.
- **`undetermined`**, "missing evidence for controls: [...]": some but not
  all referenced controls do.
- **`undetermined`**, "no evidence collected for any control": none do
  (the common case today, for every KSI-SVC indicator, against real
  collector output - proven directly in
  `evaluate_test.go`'s `TestEvaluateSVCAgainstRealCollectors`).
- **`not_applicable`**: the indicator has no associated controls in the
  dataset (a defensive case; no KSI-SVC indicator hits it today, but
  future families might).

`not_satisfied` and `requires_attestation` are both real values in the
`FR-6.6` enum (`internal/backends/fedramp20x/status.go`) that this module
never returns. That is deliberate, not an oversight: reaching either one
honestly needs content this ticket didn't review -
`not_satisfied` needs a per-control-type "is this value good" predicate,
`requires_attestation` needs the crosswalk analysis' own
non-derivable-controls list (`docs/crosswalk-analysis.md` section 9)
threaded through. Both are real follow-on work, not a promise this module
makes and breaks.

**Only KSI-SVC got a real module this session.** The other nine families
fall through to `notImplemented` in `evaluate.go`, which emits an honest
`undetermined: "no Rego evaluation module implemented yet for this KSI
family"` for every one of their indicators - present in `Evaluate`'s
output, never silently omitted, so `FR-6.7`'s coverage report can account
for all ten families from day one even though only one is real.

**Rego is embedded into the binary, not read from disk at runtime.**
`go:embed` cannot reach outside the directory of the file that declares
it, and `rego/` (deliberately at the repo root, not under `internal/`,
since `rego/ksi/README.md` already commits it to a separate Apache-2.0
release) is a sibling of `internal/`, not a descendant. `rego/embed.go`
makes `rego/` itself a tiny Go package - `package rego`, one
`//go:embed ksi` directive, nothing else - so `internal/backends/fedramp20x`
can import it and the compiled binary carries its rule modules with it,
per `NFR-1`.

**Testing is Go-only, not `opa test`.** `internal/backends/fedramp20x`'s
Go test suite runs the embedded Rego through OPA's own Go SDK
(`github.com/open-policy-agent/opa/v1/rego`) and asserts on the decoded
results. `make check` stays a single `go test ./...` invocation with no
new external tool dependency in CI; a native `*_test.rego` file OPA's own
`opa test` CLI could also run was considered and rejected for now, since
nothing in this repo's CI would ever run it, which would make it a false
signal of coverage rather than a real one.

## Consequences

Positive. The first KSI family evaluates honestly against real collector
output today (everything `undetermined`, correctly), the evaluation
mechanism (input construction, module loading, result decoding) is now
proven end to end, and adding the next nine families is close to
mechanical - copy `svc.rego`'s structure, no new Go plumbing needed. The
`notImplemented` fallback means `Evaluate`'s output shape (one row per
indicator, always) never changes as families are filled in one at a time.

Negative. Every `KSI-SVC-*` indicator, and every indicator in the other
nine families, reads `undetermined` in any report generated today - there
is no `satisfied` output to show a design partner or assessor yet outside
a synthetic test fixture. That is a real gap against `REQUIREMENTS.md`
section 17.1's exit criterion ("coverage report shows at least 60% of
applicable rules evidenced automatically"), not a hidden one - closing it
needs both more collectors (more controls with any evidence at all) and
the `not_satisfied` predicates this ADR deferred.

Open. Whether `not_satisfied` predicates belong in the same per-family
`.rego` file as the coverage check, or in a separate module reviewed and
approved indicator-by-indicator, is not decided. Given how much
compliance judgment a single predicate like "are these four
public-access-block flags all `true`" carries, the latter - smaller,
individually-reviewable diffs - is probably right, but that's a call for
when the first real one is written, not now.
