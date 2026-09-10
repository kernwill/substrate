# ADR 0004: Attestation as a third IR type, alongside Node and Edge

Date: 2026-09-10
Status: Accepted

## Context

`docs/crosswalk-analysis.md` section 9 (T-001) found that a single NIST
800-53 control can split cleanly into a mechanically-derivable portion and
a purely procedural, human-performed portion that no collector will ever
observe or infer from infrastructure. The worked example is cryptographic
key management: automated rotation and key-policy configuration is a
normal collected fact, but some frameworks additionally require a manual,
dual-control key ceremony performed by two named humans and recorded on a
signed form. Nothing in Terraform, Kubernetes, CI config, or a cloud API
can ever produce that second fact.

This was folded into `docs/REQUIREMENTS.md` as two new IR requirements
before this ticket started:

- FR-5.8: the IR must represent partial control satisfaction rather than
  collapsing a control into one boolean or enum value.
- FR-5.9: a node stores the underlying measurement, never a verdict
  computed from it (log retention as an integer day count, not "meets
  retention requirement").

FR-5.8 needs a concrete answer inside T-010's type-only skeleton: if a
control's non-derivable portion is never silently absent (silence reads as
"never checked," which violates this project's "absence of evidence is
not evidence of compliance" principle), something has to represent "a
human attested to this" as a first-class fact in the graph.

Two ways to represent that were considered:

1. Add a third value to `provenance.Basis` (today `Declared` and
   `Observed` only) and let a Node carry it.
2. Add a new, separate type - `Attestation` - alongside `Node` and `Edge`.

Option 1 was rejected. FR-4.2 is a MUST requirement stating every fact is
tagged `declared` or `observed` as a first-class field - a closed
dichotomy, not something this ticket was asked to reopen. It also
overloads Node, which per FR-5.9 exists to carry a measurement; an
attestation has no measurement to make, only testimony, and forcing it
through Node's `Kind`/`Attributes` shape would invite exactly the kind of
verdict-shaped attribute FR-5.9 exists to rule out (e.g. an `Attributes`
entry like `"ceremony_performed": "true"`, which is a verdict, not a
measurement).

## Decision

Add `ir.Attestation` as a third top-level type, structurally similar to
`Node` (`ID`, `ControlFamily`, `Controls`, `SchemaVersion`, an embedded
`provenance.Record`) but with `Statement` and `Attester` in place of
`Kind`/`Attributes`, and no measurement field at all. `Graph` gains an
`Attestations []Attestation` slice alongside `Nodes` and `Edges`, with its
own JSON Lines writer/reader (`WriteAttestationsJSONL`,
`ReadAttestationsJSONL`) following the existing sort-then-encode pattern,
and its own duplicate-ID check in `Graph.Validate`.

`Attestation.Validate` additionally requires `Provenance.Basis ==
Declared`. An attestation is definitionally someone's declared testimony;
nothing observes a human ceremony via a live API call, so an `Observed`
attestation would be a modeling mistake worth rejecting at construction
time rather than downstream.

The IR still computes no verdict anywhere. A control's coverage - whether
its derivable portion plus its attestation portion together amount to
`satisfied`, `requires_attestation` (FR-6.6), or something else - remains
entirely a backend concern (FR-6's Rego mapping), consistent with T-010's
"types only, no mapping logic" and this package's now-explicit
measurements-not-verdicts invariant (`doc.go`, `Node`'s doc comment).

## Consequences

Positive. FR-5.8's split is representable without touching FR-4.2's
Declared/Observed dichotomy, without smuggling a verdict into `Node`, and
without any mapping logic entering this package. A backend can now query
`Graph.Attestations` for a control the same way it queries `Graph.Nodes`,
and the coverage report (FR-6.7) has a real, distinct signal to render as
`requires_attestation` instead of collapsing it into `undetermined`.

Negative. A third type means a third thing every future consumer of the
IR (backends, `substrate ir query`, snapshot retention) has to know about.
`Attestation` deliberately mirrors `Node`'s shape closely to keep that
cost low.

Open. `Attestation` does not link to any `Node` via `Edge` (`Edge.From`/
`To` remain `NodeID`-only). Nothing in FR-5.8 or the crosswalk analysis
asked for that link, and adding it now would be speculative - if a future
backend needs to say "this attestation supplements this specific Node's
evidence" rather than just "this attestation covers this Control," that
is a real requirement to capture when it appears, not to guess at here.
