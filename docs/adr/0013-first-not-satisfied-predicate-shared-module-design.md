# ADR 0013: First `not_satisfied` predicate - shared module, immediate-override propagation

Date: 2026-09-18
Status: Accepted

## Context

`docs/adr/0007` deliberately shipped `KSI-SVC` (and later `KSI-IAM`,
`KSI-CNA`) as evidence-coverage-only: `satisfied` means every referenced
control has *a* node, never that the node's collected value is actually
good. It left one question explicitly open:

> Whether `not_satisfied` predicates belong in the same per-family
> `.rego` file as the coverage check, or in a separate module reviewed
> and approved indicator-by-indicator, is not decided... that's a call
> for when the first real one is written, not now.

This is that ticket. `AC-3` (an S3 bucket's four Block Public Access
flags) is the first predicate, chosen for three reasons: it's ADR
0007's own worked example, it's a clean boolean check with no
ambiguity, and the self-test fixture
(`/Users/willkern/substrate-self-test`) already encodes both directions
for free (`app_data`: all four `true`; `app_logs`: all four `false`).

Proposed and approved before any Rego was written, per this project's
compliance-content review practice - both the predicate itself and the
propagation mechanics below.

## Decision

**Predicates live in a new shared module, `rego/ksi/predicates/
predicates.rego` (package `fedramp20x.ksi.predicates`), keyed by
control ID, not duplicated inside each family file.** `AC-3` is already
referenced by three `KSI-IAM` indicators (`APM`, `ELP`, `JIT`) and will
show up in future families too; one authored-and-reviewed-once
predicate per control beats N copies drifting independently.
`internal/backends/fedramp20x`'s `compileFamily` now loads this module
alongside every family's own, unconditionally - cheap, and inert for a
family module that never imports it.

**Node attribute values now reach Rego at all.** `regoNode` (`input.go`)
had no `Attributes` field until this ticket - only `ID`, `Kind`, and
`Controls` - because coverage-only checking never needed to look past
"does a node exist." A predicate needs the actual collected value
(`ir.Node.Attributes`, FR-5.9's flat string map), so this ticket adds
it, with the same non-nil-empty-map discipline as `Controls` (see
Consequences).

**Propagation into an indicator's status, in priority order:**

1. Zero referenced controls → `not_applicable` (unchanged).
2. **Any referenced control with evidence that fails its predicate →
   `not_satisfied`, immediately - regardless of how many of the
   indicator's other controls remain completely uncollected.**
3. Otherwise, every referenced control has evidence → `satisfied`
   (unchanged).
4. Otherwise, some but not all → `undetermined`, naming the missing
   ones (unchanged).
5. Otherwise, none → `undetermined`, "no evidence at all" (unchanged).

Rule 2 is the real decision. The alternative considered and rejected:
require full coverage *before* ever checking predicates, so
`not_satisfied` only fires once every referenced control is evidenced
and something in that complete picture is bad. That's more
conservative-looking but actually worse: an indicator like
`KSI-IAM-ELP` references 34 controls, and waiting for all 34 to have
collectors before ever surfacing a *provably real* problem in the one
we can already check would mean sitting on a known bad value
indefinitely. `CLAUDE.md`'s "fail visible, never fail silent" reads the
other way - a proven violation is real, actionable information today,
independent of what else hasn't been checked yet, the same way a human
auditor reports "this bucket is wide open" without waiting to finish
reviewing everything else.

## Consequences

Positive. The mechanism is real, not speculative: `evaluate_test.go`
proves the override fires even amid the indicator's other controls
being entirely uncollected
(`TestEvaluateIAMNotSatisfiedEvenWithMassiveMissingCoverage`), and that
it wins over an otherwise-satisfied full-coverage case
(`TestEvaluateIAMFullCoverageButPredicateFailsIsNotSatisfied`). A real
correctness bug surfaced while adding node attributes to the Rego
input: `regoNode.Attributes` needed the identical non-nil-empty-map
treatment `docs/adr/0012`'s sibling work already found for
`regoIndicator.Controls` (a nil Go map/slice serializes as JSON `null`,
and a Rego comparison against a missing/null field is undefined, not
false) - fixed in the same commit, with a dedicated test
(`TestBuildInputNodeAttributesPassThrough`).

**Open, tracked concern (flagged for future revisit, not resolved
here):** rule 2 means one misconfigured resource can flip an entire
multi-control indicator's status - `KSI-IAM-ELP` referencing 34
controls will read `not_satisfied` the moment even one evidenced
control among those 34 fails, the same as it would if every single one
failed. The underlying signal is correct (see the Decision section's
reasoning), but a `gate` PR comment surfacing "`KSI-IAM-ELP` regressed
to not_satisfied" reads like a much bigger event than "one bucket,"
and that messaging gap could matter once this is visible in a real
run rather than a unit test. Tracked in `docs/REQUIREMENTS.md` section
31, item 9. Revisit once `gate`/PR-comment rendering (`docs/adr/0011`)
has real `not_satisfied` output to work with, not before.
