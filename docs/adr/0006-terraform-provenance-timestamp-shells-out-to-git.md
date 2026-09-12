# ADR 0006: Terraform fact provenance shells out to `git log` for its timestamp

Date: 2026-09-10
Status: Accepted

## Context

Implementing FR-2.1 (Terraform parsing) meant deciding what
`provenance.Record.Timestamp` should hold for a fact parsed from a
`.tf` file. That field's own doc comment is explicit about what it
means: "when the fact was true at the source (a file's last commit, an
API response's observation time) - a property of the collected data,
not of when the compiler happened to run."

The first implementation used the file's filesystem modification time
(`os.Stat(path).ModTime()`). This looked reasonable in isolation - it's
deterministic across repeated runs against an unchanged file - but a
golden-fixture regeneration for `testdata/fixtures/minimal` surfaced the
real bug before it was committed: git does not preserve mtimes, so the
exact same committed file content produces a different,
environment-dependent timestamp on every fresh checkout. That is
precisely the class of value NFR-3 ("byte-identical output for
identical inputs") and this project's broader "no wall-clock time in
output" principle exist to rule out - it just arrives via checkout time
instead of compile time.

Three options were considered:

1. Shell out to `git log` for each file's last commit time.
2. Use a pure-Go git library (e.g. `go-git/go-git`) to read commit
   history without invoking an external binary.
3. Defer the correct behavior, ship a documented placeholder timestamp
   (e.g. the Unix epoch) for now, and track real provenance as a
   follow-up.

## Decision

Shell out to `git log -1 --format=%cI -- <file>`, run with its working
directory set to the file's own directory so it resolves correctly
regardless of where the actual repository root is. If git is not on
PATH, the directory isn't a git working tree, or the file has no commit
history, `Parse` returns a real error - never a guessed or
placeholder timestamp. Terraform files must be committed to git for
`substrate compile` to run against them.

This is a direct tension with NFR-1 ("single static binary, no runtime
dependencies"): the binary now has a real runtime dependency on the
`git` executable being present, for this code path. That tradeoff was
made deliberately rather than by default. Option 2 (a pure-Go git
library) keeps the binary self-contained but adds a substantial new
dependency - `go-git` pulls in a meaningful transitive tree - for
exactly one field, which sits awkwardly next to CLAUDE.md's "do not add
dependencies casually." Option 3 (a placeholder) was rejected outright:
it is exactly the kind of guess FR-2.3 forbids ("never guess"), and a
placeholder timestamp baked into a golden fixture or a real compiled
artifact is worse than a loud error, not better - it looks like real
provenance while being fabricated.

`git` being present is a reasonable assumption for this tool's actual
operating environment: it compiles a customer's own Infrastructure-as-
Code, which is committed to git in virtually every real deployment
(this is also implicitly assumed by GitHub Actions being a MUST-priority
front-end source, FR-2.6). A customer running this tool outside a git
checkout at all is an edge case worth a clear error, not a design
center to optimize the dependency graph around.

## Consequences

Positive. Provenance timestamps for Terraform facts are now genuinely
reproducible: the same commit produces the same timestamp on every
checkout, on every machine, forever - matching NFR-3's actual intent
rather than technically satisfying "deterministic within one machine."

Negative. `substrate compile` (and any other command touching Terraform
parsing) requires `git` on PATH and requires the parsed files to have at
least one commit. A file that has never been committed at all correctly
gets a loud error (`CommitTime`'s own "has no git commit history" case).

But a file that was committed once and then edited locally without a new
commit does not: `git log -1 -- <file>` only ever answers "when was this
file's history last touched," which says nothing about whether the
working tree currently matches that commit. `Parse` reads the file's
*current* on-disk content (`os.Open`/`os.ReadFile`) but stamps it with
that stale, pre-edit commit timestamp - silently, with no error and no
distinguishing signal anywhere in the resulting fact. This ADR's original
consequences section described the friction case ("an uncommitted,
in-progress .tf file... cannot be compiled yet") as if it were a hard
stop; it is not, for exactly the files where the mismatch is real - only
a file with *zero* commits ever fails loudly. That gap was found by a
`/code-review` pass against all three frontends now sharing this
package, not caught when this ADR was first written against Terraform
alone.

This remains a real workflow friction worth revisiting (e.g. a
clearly-labeled "uncommitted" provenance state instead of silently
reusing the last commit's timestamp), but the revisit should fix the
silent mismatch specifically, not just the already-loud all-zero-commits
case.

Resolved. The "unproven" generalization question this ADR originally
posed - whether Kubernetes manifests and GitHub Actions workflow files
should get the same git-commit-time treatment as Terraform - is resolved
by FR-2.4/2.5 and FR-2.6's own landings:
`internal/frontend/kubernetes.Parse` and
`internal/frontend/githubactions.Parse` both call `vcs.CommitTime`
exactly as Terraform's `Parse` does (see `internal/frontend/vcs`'s own
package doc comment, which now states this directly: "every frontend
collector that reads static files should use this package rather than
reinvent the same tradeoff file by file"). The silent stale-timestamp gap
above is therefore not a Terraform-specific loose end; it applies
identically to all three frontends this project has today, and to any
future one built on `vcs.CommitTime`.

If this proves to be a recurring source of friction (customers whose
CI checks out a shallow or detached clone where `git log` behaves
unexpectedly, for instance), revisit toward option 2 (a pure-Go git
implementation) rather than silently degrading to option 3 (a
placeholder) under pressure.
