# ADR 0012: Coverage report buckets, and what "applicable" excludes

Date: 2026-09-18
Status: Accepted

## Context

FR-6.7 ("Coverage report: automated vs human-attested vs not visible")
had no code. `substrate compile` already computes everything the report
needs - `fedramp20x.Evaluate` returns one `IndicatorResult` per indicator
in the dataset, always, naming every family even when a family has no
Rego module yet (`docs/adr/0007`) - but nothing aggregated that list into
the three-bucket shape the requirement, `docs/crosswalk-analysis.md`
section 9, and `docs/REQUIREMENTS.md` section 17.1's exit criterion
("coverage report shows at least 60% of applicable rules evidenced")
all describe.

This is reporting over already-approved status data, not a new
compliance-content decision: no indicator gets classified any
differently by existing than it did before this ticket, and no new
control mapping was authored.

## Decision

`fedramp20x.Coverage(results []IndicatorResult) CoverageReport` buckets
by `Status` alone:

- **Automated** — `Satisfied` or `NotSatisfied`: a real verdict, either
  direction.
- **HumanAttested** — `RequiresAttestation`.
- **NotVisible** — `Undetermined`: a real gap, whatever the reason
  (missing evidence, no Rego module for the family yet).
- **NotApplicable**, tracked but not one of the three named buckets — an
  indicator with no controls in the dataset is out of scope, not "not
  visible."

**`Applicable` is `Automated + HumanAttested + NotVisible`, and
`PercentAutomated` divides by it, not by the total including
`NotApplicable`.** Section 17.1's exit criterion says "applicable rules,"
and an indicator the dataset marks out of scope was never a candidate
for automation in the first place - counting it against the denominator
would understate coverage for a reason that has nothing to do with how
much of the product is built.

Computed overall and per KSI family, family rows sorted by family code
(`Evaluate`'s own reproducibility discipline, applied here too - map
iteration order never reaches the output). Written as `<out>/
coverage.json` alongside `ksi_results.json`, and folded into `compile`'s
one-line stdout summary.

`compile.go`'s `formatCoverage`, unlike its neighboring `statusTally`,
never omits a zero-valued term. `statusTally` hides zero-count statuses
because most of them (`not_satisfied`, `not_applicable`,
`requires_attestation`) are genuinely absent today and printing three
permanent zeros would be noise. Coverage is the opposite case: "0
automated, 0 human-attested, 46 not visible" *is* the message FR-6.7
exists to surface, every run, not noise to suppress until it turns
nonzero.

## Consequences

Positive. FR-6.7 is real now, and honest against real collector output:
the regenerated `testdata/fixtures/minimal` golden shows all 46
indicators, across all 10 families, `not_visible`, 0% automated -
matching `docs/adr/0007`'s disclosed state of the backend exactly, not
a rosier number. Every KSI family the vendored dataset defines appears
in `coverage.json`'s `families` list from day one, same as
`ksi_results.json` already does, so adding the next Rego module changes
some rows' counts without changing the report's shape.

Negative / open. `CoverageReport` has no rendering beyond raw JSON and
the one-line stdout summary - no `substrate coverage` command, no
Markdown report for a human reader outside a CI log. That's deferred,
not decided against; nothing here blocks adding one once there's a real
reason to (a design partner asking for one, most likely, per section
17.1). `HumanAttested` will read 0 in every real run until a future,
separately-reviewed ticket threads `docs/crosswalk-analysis.md` section
9's non-derivable-controls list into an actual family's Rego module and
starts returning `RequiresAttestation` - `docs/adr/0007`'s own "real
follow-on work, not a promise this module makes" language applies here
unchanged.
