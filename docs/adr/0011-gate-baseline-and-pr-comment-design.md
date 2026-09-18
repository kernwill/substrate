# ADR 0011: `substrate gate`/`baseline update` design, including PR comments

Date: 2026-09-17
Status: Accepted

## Context

FR-7 (the CI gate) had no code at all: no `gate` command, no `baseline
update` command, and everything `substrate compile` produces
(`ksi_results.json`) sat there unconsumed by anything that could
actually fail a build. This is Phase 1's own centerpiece exit
criterion - "CI gate running in at least one design partner pipeline"
- and the one piece that turns a compiled evidence graph into
something that actually gates a pull request rather than just
describing one.

Several design forks needed resolving, more than usual for one ticket,
so this ADR is broader than most:

1. Does `gate` re-run `compile` itself, or diff two already-compiled
   files?
2. What exactly counts as a "regression"?
3. FR-7.4 requires posting a PR comment - does that ship now, alongside
   the rest of gate, or later? (Discussed directly with the user before
   building: the case for shipping it now won on the strength of it
   being a disclosed MUST-requirement gap otherwise, even though no
   design partner exists yet to build it against exactly - see the
   session's own discussion for the full tradeoff.)
4. FR-7.6 wants an "approval trail... recorded in the SDR" - the SDR
   (FR-6.4) doesn't exist in this codebase at all.

## Decisions

**`gate` and `baseline update` diff already-compiled files; neither
runs `compile` itself.** Same single-responsibility, composed-in-a-
pipeline shape ADR 0009 already established for `collect`/`compile`:
`substrate compile` produces `ksi_results.json`; `substrate baseline
update --current <that file> --out <baseline>` records it;
`substrate gate --baseline <that file> --current <a later run's
ksi_results.json>` diffs the two. A CI workflow chains these as
separate steps, the same way it already chains `collect` then
`compile --runtime`.

**A regression is exactly: an indicator `Satisfied` in the baseline
that is not `Satisfied` in the current run.** Everything else is
reported but never fails the gate:

- `undetermined` → `undetermined` (even with a different `Reason`,
  e.g. different missing controls) is **not** a regression - neither
  state was ever a real compliance signal, and with only two runtime
  collectors built so far, nearly every indicator is `undetermined`
  today; treating a changed `Reason` string as a regression would make
  the gate fail on almost every commit for no real cause.
- An indicator present in the current run but absent from the baseline
  (a genuinely new one, e.g. after a ruleset version bump) is reported
  as **New**, never a regression - FR-7.3 is about a rule that
  *regressed*, and nothing can regress that didn't previously exist to
  the baseline at all.
- An indicator present in the baseline but absent from the current run
  is reported as **Missing**, also never a regression on its own -
  that shape of change (the ruleset itself changed) is FR-8.12's own
  "ruleset migration" reporting job, a separate, later feature; `gate`
  surfaces the anomaly rather than pretending nothing happened, but
  doesn't try to own the deeper analysis of why it happened.
- `not_satisfied` → `satisfied` (or any other non-`Satisfied` → 
  `Satisfied` transition) is an **Improvement**, reported positively,
  never a failure.

**FR-7.5's severity policy is `--severity error|warn`.** `error` (the
default) fails the gate (exit 1) on any regression; `warn` reports the
exact same regressions but always exits 0. Nothing about detection
changes between the two - only whether a regression is allowed to fail
the build.

**PR comments ship now** (per direct discussion, overriding this ADR's
own first-drafted recommendation to defer). Built as a minimal,
dependency-free REST client (`github.go`, `net/http` +
`encoding/json` only, three endpoints: list/create/update an issue
comment - PRs use the `issues` comment endpoints) rather than pulling
in a full GitHub SDK for a surface this narrow, per CLAUDE.md's "do not
add dependencies casually."

- **Context comes from GitHub Actions' own ambient environment**
  (`GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and the PR number parsed out of
  the JSON file `GITHUB_EVENT_PATH` points at), not new flags - the CI
  environment already has this information, and requiring a customer
  to re-supply it via flags would be pure friction with no benefit. A
  non-PR-triggered run (a push to main, a schedule) has no
  `pull_request` key in its event payload and `--pr-comment` becomes a
  documented no-op (a warning, not a failure - see below), which is the
  correct behavior for that trigger type, not an error case to special-
  case around.
- **One comment, updated in place, not one new comment per run.** A
  hidden HTML marker (`<!-- substrate-gate -->`) identifies substrate's
  own comment; a rerun on the same PR (a second push) finds and PATCHes
  it rather than posting a duplicate - the same pattern most PR-
  commenting CI bots use, chosen specifically to avoid spamming a PR's
  timeline on every push to an active branch.
- **A green run touches nothing new, but does resolve a stale
  comment.** `postGateComment` runs on every `--pr-comment` invocation,
  not only when a regression exists; it skips entirely when there is
  neither a regression nor a prior marked comment (nothing to say, and
  nothing previously said that needs correcting), but if a marked
  comment already exists, it always updates it - to the current
  regression report, or to an explicit "previously reported
  regression(s) are now resolved" message. (This corrects this ADR's
  own first-drafted design - see "Post-review fixes" below.)
- **A comment-posting failure never changes the gate's own exit code.**
  The regression decision (and its exit code) is computed and printed
  to stdout/stderr entirely before `postGateComment` is ever called;
  if posting fails (rate limit, network blip, missing token outside
  CI), that failure is reported as a warning on stderr and nothing
  else changes. A GitHub API hiccup must never be able to flip a real
  regression into a false pass by erroring out early, nor fail an
  otherwise-clean gate run over a concern that has nothing to do with
  compliance posture.

**FR-7.4's other half - naming "the file and line" - is real, not
symbolic.** `gate --nodes <file>` (optional) accepts the matching
`nodes.jsonl` `compile` also wrote, and resolves a regression's
*baseline* `Evidence` node IDs (the facts that proved it Satisfied
*before* the regression) to `path:line` via `Provenance.Locator`. This
needed real design: `IndicatorResult` itself carries only node ID
strings, not locations, so `gate` had to read a second file to answer
"where" at all. Citing the baseline's evidence, not the current run's
(which usually has none, precisely because it regressed), is
deliberate - it answers "what used to make this pass," the more useful
half of the story for a reviewer.

**FR-7.6's "approval trail... recorded in the SDR" ships as a
documented stand-in, not the SDR.** `Baseline` (`baseline.go`) records
`ApprovedBy` (from local `git config user.name`/`user.email` - the same
identity a commit made right now would carry, not an application-level
login system this project has none of) and `ApprovedAt`/`GitCommit`
alongside the KSI results. This is explicitly **not** FR-6.4's Security
Decision Record (an append-only log with a current-state projection) -
FR-6.4 doesn't exist in this codebase at all yet. Building real SDR
infrastructure just to satisfy this one field would be a large,
unreviewed detour into unbuilt FR-6 territory; recording a minimal,
honest trail inside the baseline file itself, and disclosing the gap
here and in `Baseline`'s own doc comment, is the same "publish gaps,
don't hide them" treatment `docs/redaction-coverage.md` and FR-6.7's
coverage report already get.

## Post-review fixes

`/code-review` (high effort, run given the new network/token surface)
found no security vulnerabilities (a separate dedicated security
review confirmed the same), but found several real correctness and
robustness gaps in the first draft of this design, all fixed:

- **A silent regression-detection bug, not just an edge case.**
  `diffResults` originally treated ANY transition away from `Satisfied`
  as a gate failure, including to `NotApplicable` (the control's own
  scope changed, e.g. a resource was removed) or `RequiresAttestation`.
  Neither means the customer's posture got worse. Fixed by narrowing
  the actual failure condition to `NotSatisfied`/`Undetermined`
  specifically (`isRegressedStatus`), with the other transitions now
  reported in a new `gateDiff.OtherChanges` category - visible, never
  silently dropped, never a gate failure.
- **Silent data-integrity failure on a duplicate indicator ID.**
  `diffResults`' original map-building silently kept only the last
  entry for a repeated Indicator ID in either input. Fixed:
  `indexByIndicator` now errors loudly on any duplicate, changing
  `diffResults`' own signature to return an error.
- **The stale-comment bug already described above** - `postGateComment`
  only fired when a regression existed, so a run that fixed one never
  touched the PR, leaving a false "regression found" comment
  indefinitely. Fixed by calling it unconditionally and having it
  decide skip/create/update itself, refactored so the decision logic
  (`(*githubConfig).postGateComment`) is a directly-testable method
  separate from environment resolution (`postGateComment`, the free
  function).
- **Pagination.** `findMarkedComment` originally fetched only GitHub's
  default 30-comment first page, so a marked comment posted several
  runs ago on an active PR was never found past that point, and every
  later run created a duplicate instead of updating in place - the
  exact spam this marker design exists to prevent. Fixed: pages through
  every page (`githubCommentsPerPage`, 100 per request) until a
  short page confirms there's no more.
- **No request timeout.** `do()` used `http.DefaultClient` (no
  `Timeout`) called under `context.Background()` (no deadline) all the
  way from `postGateComment`'s own top-level call - a GitHub API stall
  could hang `runGate` indefinitely, worse than the "never fails the
  gate over a network issue" behavior this design already documented.
  Fixed with two layered bounds: `githubHTTPClient`'s own `Timeout`
  (`githubRequestTimeout`, 15s) caps each individual request, and
  `runGate`'s wrapping context (`githubOperationTimeout`, 30s) caps the
  whole find-then-create-or-update operation, generous enough to allow
  a few paginated requests without letting a genuine stall hang the job.
- **A GitHub-Actions-specific redaction false positive, found in the
  same pass**: `internal/redact`'s generic key-name matching flags
  "token" as a substring, which matches the standard OIDC permission
  scope name `id-token` (`permissions: {id-token: write}`) - silently
  replacing a real, non-secret scope level ("write") with
  `[REDACTED]` before the already-reviewed AC-6 evidence mapper
  (`githubactions/ir.go`'s `mapPermissions`) ever read it. Fixed in
  `internal/frontend/githubactions/parse.go` by exempting the
  top-level `permissions` block from the generic redaction pass
  entirely (every value in it is one of a fixed, closed enum, never
  secret material) rather than narrowing `KeyLooksSecret` itself, which
  would have weakened the "token" pattern everywhere else in the
  codebase for the sake of one field.
- **Duplicated write logic and a stale doc comment**, both minor:
  `baseline.go` hand-rolled the same create/encode/checked-close
  sequence `compile.go`'s `writeArtifact` already defines once - now
  calls it directly. `compile.go`'s own doc comment still described
  each frontend's raw JSON as written verbatim from source, which
  stopped being true the moment redaction (ADR 0010) started running
  inside every `Parse` call - corrected to say so explicitly.

## Consequences

Positive. Phase 1's centerpiece exit criterion is now real: a customer
can run `compile` → `baseline update` once, then `gate` on every
subsequent PR, and a previously-Satisfied indicator regressing actually
fails the build - with the regressed rule, its prior status, and (when
`--nodes` is given) where its old evidence lived, all named in both the
CI log and, now, the PR itself.

Negative. `ApprovedBy`'s git-identity approach is spoofable by anyone
who can set their own git config - acceptable for now (this is an
approval *trail*, not an approval *gate* with real authorization
behind it; nothing here claims otherwise), but a real access-control
model is exactly the kind of thing FR-6.4's actual SDR would need to
get right, and this stand-in should be revisited, not extended, once
that exists.

Open. `gate`'s PR-comment integration was built against GitHub Actions'
own documented environment variables and REST API shape without a real
design partner's pipeline to validate against - the same risk flagged
when this was discussed before building. FR-7.7 (GitLab CI support) is
untouched; nothing in `github.go` generalizes to it, and a GitLab
equivalent (merge request notes, a different CI env-var vocabulary)
would need its own file, not a refactor of this one.
