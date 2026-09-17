# ADR 0009: `substrate collect` is a separate command, not a `compile` flag

Date: 2026-09-17
Status: Accepted

## Context

`internal/frontend/collectors/aws` had two fully built, fixture-tested
runtime collectors (S3, IAM) with nothing in `cmd/substrate` ever calling
either one - the same "built in isolation, never actually run" gap
`docs/adr/0007`/FR-6's own wiring closed for the Rego backend a few
commits earlier. Closing it for FR-3 meant deciding how a CLI command
that needs live AWS credentials fits next to `compile`, which - until
now - never touched a network at all.

Two shapes were considered:

1. A flag on `compile` itself (e.g. `--collect-aws`) that, when set,
   builds an AWS client via the SDK's default credential chain and runs
   the runtime collectors inline, merging their output into the same
   evidence graph the static frontends build in the same process.
2. A separate `substrate collect --out <dir>` command that only runs
   the runtime collectors and writes their raw output to disk, read
   back in later by `compile --runtime <dir>` if the caller wants that
   evidence merged in.

## Decision

Option 2. `docs/REQUIREMENTS.md`'s own planned CLI surface already
listed `collect` and `compile` as separate commands before either was
implemented - this decision makes that split real rather than
introducing a new one.

The substantive reason, not just "the docs already said so": `compile`
is the command a customer's CI runs on every pull request (FR-7's whole
premise). A PR has no reason to need live AWS credentials - the PR's own
diff is Terraform/Kubernetes/CI-config text, nothing more - so folding
AWS access into `compile`'s own hot path would mean every PR-triggered
run pays for (and needs to be trusted with) network access to a
customer's AWS account it fundamentally doesn't need. Runtime
collection's own natural cadence is different anyway: FR-8.9 calls for
"scheduled KSI revalidation independent of pull requests," which is
exactly `collect` running on a timer, writing fresh `aws_s3.json`/
`aws_iam.json`, with `compile` runs in between reading whatever `collect`
last wrote rather than each one re-collecting for itself.

**Credential handling stays exactly where `internal/frontend/collectors/aws`'s
own doc.go already said it lives**: `collect.go` is the one and only
place in the CLI that calls `config.LoadDefaultConfig` and constructs
real `s3.Client`/`iam.Client` values; `compile.go` never touches AWS
credentials at all, even conceptually - it only ever reads plain JSON
files back off disk.

**Publish logic is shared, not re-implemented.** `collect.go`'s
`writeCollectOutput` calls the exact same `publishOutput`/`publishFromTmp`
`compile.go` already had (both live in package `main`, so no export or
move was needed) - the atomic-write-with-restore-on-failure guarantee
`compile`'s own `--out` already had now applies to `collect`'s `--out`
for free, with no new bug surface to introduce.

**JSON tags were added to every `internal/frontend/collectors/aws` type**
(`Bucket`, `IAMUser`, and their nested types) as part of this same
change. They had none before - nothing had ever serialized them to
disk - and once `collect` writes them and `compile --runtime` reads them
back, their field naming becomes a real interchange format between two
commands, not an internal implementation detail either command is free
to rename without consequence. `docs/adr/0008`'s reasoning about
`compile`'s own artifact shapes mattering (golden fixtures, "that diff
is a change in what we assert to the federal government") extends here:
a round-trip test (`TestS3GraphJSONRoundTrip`, `TestIAMGraphJSONRoundTrip`)
guards the tags themselves, and `TestCompileIngestsRuntimeEvidence`
guards the full `collect` → `compile --runtime` path end to end using
`collect.go`'s own `writeCollectOutput`, not a hand-written fixture -
so the test stays honest if that format ever changes instead of
silently drifting from what `collect` actually produces.

**`--runtime` is optional and changes nothing when omitted.** Every
existing `compile` invocation (and its golden fixture) behaves
identically without `--runtime` - this is not a breaking change to a
command that already has real users' CI pipelines depending on its
current behavior, it is a pure addition.

## Consequences

Positive. Two previously-inert collectors are now reachable from the
CLI. The credential boundary this codebase has stated since
`internal/frontend/collectors/aws/doc.go` was first written (`collect.go`
builds clients, the collector package never does) is now actually
enforced by which file imports what, not just documented intent.

Negative. A customer wanting Observed evidence in their compiled package
now needs to run two commands in the right order (`collect` then
`compile --runtime <that output>`) rather than one - a real operational
step, and one `docs/SETUP.md` or a CI-pipeline example will need to
walk through once this reaches actual customer-facing documentation
(neither exists yet for this feature).

Open. `collect` always runs every collector this package has (today:
S3 and IAM) unconditionally, with no way to run a subset - fine at two
collectors, likely wants a flag (`--only s3,iam` or similar) once
CloudTrail/KMS/VPC/Config/GuardDuty/SecurityHub and Okta exist and a
customer's read-only role might not cover all of them yet. Not decided
here; revisit when the third collector lands.
