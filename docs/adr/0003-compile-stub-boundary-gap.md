# ADR 0003: `cmd/substrate/compile.go` is a stub outside boundary enforcement

Date: 2026-09-09
Status: Accepted, revisit before Phase 1 front-end work lands

## Context

T-008 added `substrate compile --source --out` as a real, dedicated CLI
command (`cmd/substrate/compile.go`) so the golden-fixture harness had
something concrete to exercise ahead of the parser
(`testdata/fixtures/minimal`). Today it does nothing but validate its own
flags and print "not implemented yet" - it does not import
`internal/frontend`, `internal/ir`, or `internal/backends`, all three of
which remain empty `doc.go` skeletons.

`scripts/check-boundaries.sh` enforces this project's three-stage
architecture (CLAUDE.md's "Architectural invariants"), but it only
inspects `internal/frontend`, `internal/ir`, and `internal/backends`
themselves. It has no rule at all about `cmd/substrate` - there was
never a reason to write one, because the CLI has always been a thin
dispatcher with no business logic of its own.

An ultra code review (session covering T-008's landing) flagged the
resulting gap: nothing today would stop a future implementation of real
compile logic from being written directly inside
`cmd/substrate/compile.go` instead of `internal/frontend` /
`internal/ir` / `internal/backends`. `make boundaries` would stay green
throughout, because it never looks at `cmd/substrate` - reproducing
exactly the kind of leak invariant #4 exists to prevent, just one layer
up from where the check currently looks.

## Decision

Accept the gap for now rather than add a speculative check with nothing
real to verify against yet: `compile.go` is a stub with zero front-end,
IR, or backend logic, so there is nothing to leak today. Extending
`check-boundaries.sh` to police `cmd/substrate`'s import graph before
that logic exists would be enforcing a rule against code that doesn't
exist, which is different from the leaks the existing four invariants
guard against (real, already-written code crossing a real boundary).

Record it here instead, per CLAUDE.md's instruction to record - not
paper over - anything that felt like it wanted to break an invariant.

## Consequences

This ADR is the trigger: the moment `internal/frontend`, `internal/ir`,
or `internal/backends` gain real logic (Phase 1, FR-2 through FR-6),
`cmd/substrate/compile.go`'s implementation must be reviewed for exactly
this leak - either it correctly delegates to those packages and contains
no parsing/mapping/emission logic of its own, or `check-boundaries.sh`
needs a fifth check constraining what `cmd/substrate` is allowed to do
directly. Whoever picks up the first real Phase 1 front-end ticket should
read this ADR before writing `compile.go`'s real body.
