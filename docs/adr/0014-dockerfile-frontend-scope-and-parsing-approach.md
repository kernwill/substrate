# ADR 0014: Dockerfile frontend - hand-rolled FROM-only parser, no new dependency

Date: 2026-09-18
Status: Accepted

## Context

FR-2.7 ("Dockerfile and base image extraction for supply chain
evidence," SHOULD priority) is the fourth static frontend and the first
one whose source format isn't already backed by a stack-table library -
`internal/frontend/terraform` has `hashicorp/hcl`,
`internal/frontend/kubernetes` and `internal/frontend/githubactions`
both have `gopkg.in/yaml.v3`. There is no equivalent pre-approved choice
for Dockerfile syntax, and CLAUDE.md is explicit that "every dependency
is something a customer's security review will ask about" - so the
first real decision here was whether this frontend needed a dependency
at all.

## Decision

**No dependency. A small hand-rolled parser, scoped to exactly one
instruction.** FR-2.7's own text is "Dockerfile AND BASE IMAGE
EXTRACTION" - not general Dockerfile linting or full-instruction-set
modeling. The only instruction this package reads is `FROM`; `RUN`,
`COPY`, `USER`, `ENV`, and everything else are never inspected.
Container-hardening concerns like non-root users are already this
project's Kubernetes frontend's job at the pod/container spec level
(FR-2.5) - re-deriving a weaker version of that from a Dockerfile's
`USER` instruction would be a second, less authoritative source of
truth for the same fact, not new evidence. A real Dockerfile parser
(there are a few `moby/buildkit`-adjacent ones) would have been
reasonable for a frontend that needed the full instruction grammar;
for "find every FROM line, split it into repository/tag/digest,"
hand-rolling roughly 150 lines was the smaller total dependency-and-
maintenance surface, matching the same reasoning ADR 0008 used for
CloudTrail's own scope decisions.

**Line-continuation handling matches Docker's default (trailing `\`),
not the full escape-directive grammar.** A Dockerfile can override its
own continuation character via a `# escape=`` `` `-directive comment;
this package always assumes the default. A real Dockerfile using the
non-default escape character would have its `FROM` lines mis-joined.
Accepted as a known, narrow gap for a SHOULD-priority frontend rather
than parsing directive comments for a case rare enough that no
production Dockerfile in this project's own testing uses it.

**Three-way classification, not two.** A `FROM` instruction's argument
resolves to exactly one of: an external image reference
(`BaseImageExternal`), the literal empty image (`FROM scratch`,
`BaseImageScratch`), or a reference to an earlier stage in the same file
(`FROM builder`, `BaseImageLocalStage`) - see `doc.go` and `graph.go`'s
own doc comments for the full reasoning. The middle and last cases are
real, resolved (`Deterministic`) facts, not "unresolved" ones: this
package knows exactly what they are. They simply carry no supply-chain-
authenticity control node, because there is no externally-sourced
component to authenticate - the same "collected but the control doesn't
apply" treatment as an unmapped resource type elsewhere in this
codebase, except here the reason is architectural (nothing external
exists) rather than "no one has reviewed a mapping yet." Only a `FROM`
whose argument contains an unexpanded build argument or variable
(`FROM ${BASE_IMAGE}`) is genuinely `Unresolved` - this package does not
track `ARG` declarations or perform variable substitution, matching
FR-2.3's "never guess" principle.

**SR-11 (Component Authenticity) reused from `githubactions`, but kept
local, not moved into the shared `internal/frontend/controls`
package.** Base-image digest-pinning and GitHub Actions'
`dependency-review-action` presence are two different facts that happen
to land on the same control - not the same fact evidenced twice
(Declared+Observed) the way `internal/frontend/controls`'s existing
entries are. Reviewed and approved explicitly before any code was
written, per this project's compliance-content discipline.

**Directory scoping matches Terraform's, not a new convention.**
`Parse(dir)` globs `Dockerfile`/`Dockerfile.*` directly in `dir`, called
from `cmd/substrate/compile.go` against `--source` itself (the same
directory Terraform parses), not a new subdirectory like Kubernetes'
`/k8s` or GitHub Actions' `/.github/workflows`. This is the same
"narrow, provisional convention, not a general answer to which files
belong to which frontend" caveat `compile.go`'s own doc comment already
carries for those two - a real repository often nests a Dockerfile
inside a service subdirectory, which this first pass does not find. A
lowercase `dockerfile` filename, also a real convention in some
repositories, is likewise not matched, to keep this first pass's glob
as unambiguous as Terraform's `*.tf`.

## Consequences

Positive. Zero new dependencies for a fourth static frontend. The
scratch/local-stage/unresolved three-way split means this frontend
never asserts SR-11 evidence for something that structurally cannot be
authenticated (an internal build stage, or nothing at all), which a
naive "just check for `@sha256:`" implementation would have gotten
wrong for exactly those two cases.

Negative/Open. Non-default escape characters, nested Dockerfile
locations, and lowercase filenames are real gaps, not follow-on
polish - the fix for any of them is "revisit this ADR's scoping
decisions," not a silent broadening of the glob or the continuation
rule. `RUN`/`COPY`/`USER`/`HEALTHCHECK` and every other instruction
remain entirely unparsed; if a future control needs one of them, that
is new parser surface and almost certainly a new compliance-content
review, not an extension of `classifyImageSpec`.
