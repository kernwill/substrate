# Fixture: minimal - notes

## What this fixture is meant to catch

The smallest realistic input touching all three Phase 1 front-end
sources at once:

- `main.tf` - an S3 bucket with versioning, KMS server-side encryption,
  and a public access block. Deliberately unremarkable: nothing here
  should read as `undetermined` once the Terraform front end (FR-2.1)
  exists, so this fixture stays useful as a "the boring path still
  works" check even as harder fixtures get added alongside it.
- `k8s/deployment.yaml` - a Deployment with a non-root, no-privilege-
  escalation, read-only-root-filesystem pod security context, plus a
  default-deny NetworkPolicy (FR-2.5's pod security context and network
  policy extraction).
- `.github/workflows/ci.yml` - a workflow with `permissions: contents:
  read` and a dependency-review job (FR-2.6).

Once the real pipeline exists, this fixture is the first thing that
must produce a byte-identical, schema-valid artifact set on every run
(NFR-3) before any more elaborate fixture is worth adding.

## Current status (T-008, before any parser exists)

`substrate compile` is not implemented yet (Phase 1: FR-2 through FR-6).
`expected/` right now records *that* fact - the stub's exit code and
stderr message - not real compiled output. This is deliberate: T-008 is
about proving the golden-fixture harness itself (walk fixtures, run the
pipeline, compare, refuse to regenerate silently) works correctly ahead
of the parser, per CLAUDE.md's "write the golden fixture before the
parser." The harness is what's under test right now, not the compiler.

`expected/` **must** be deliberately regenerated and its diff reviewed
the moment `substrate compile` does real work against this fixture -
that diff is the first real evidence-graph output this project ever
asserts, which is exactly the kind of diff CLAUDE.md says to never
accept by editing `expected/` by hand.
