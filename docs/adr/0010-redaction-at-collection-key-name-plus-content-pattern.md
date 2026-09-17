# ADR 0010: Redaction at collection, key-name matching plus content patterns

Date: 2026-09-17
Status: Accepted

## Context

`internal/redact` was a package-doc-comment stub with no implementation
from the project's first commit through every frontend collector built
since - a real safety gap, not a missing feature: CLAUDE.md's own
non-negotiable design principles state "Redact at collection. Secrets,
tokens, PII scrubbed before anything touches disk. Assume every
artifact gets committed to a customer repo," and FR-4.4/FR-4.5 (MUST)
require exactly this, tested and documented. Every raw per-frontend
artifact `substrate compile` and `substrate collect` write
(`terraform.json`, `kubernetes.json`, `github_actions.json`,
`aws_s3.json`, `aws_iam.json`) captures collected data close to
verbatim - a hardcoded secret anywhere in a customer's Terraform,
Kubernetes manifests, or GitHub Actions workflows would have reached
disk unredacted.

## Decision

**Two independent detection layers**, not one:

1. **Key-name matching** (`KeyLooksSecret`): a map key whose name
   matches a documented list of secret-shaped fragments
   (`password`, `token`, `api_key`, ...) redacts its entire value
   wholesale, regardless of content. This is the primary layer -
   IaC/manifest formats are naturally key-value shaped, and a field
   *named* `password` is a far more reliable signal than any pattern
   matched against its *content* could be.
2. **Content pattern matching** (`String`): a small, deliberately short
   list of unambiguous formats (PEM private key blocks, AWS access key
   IDs, JWTs) redacted wherever they appear, independent of key name -
   defense-in-depth for a secret sitting under a name that gives no
   hint (a bare `value`).

Both layers are documented exhaustively in `docs/redaction-coverage.md`,
including what they deliberately do not cover (an unstructured secret
under a non-obvious key name; AWS secret access keys, mitigated instead
by this project's own collectors never gathering them; PII beyond what
a JWT-shaped value happens to carry). Per `docs/REQUIREMENTS.md`'s own
"publishing gaps builds more trust than hiding them" principle, applied
to redaction rather than KSI coverage.

**Deliberately biased toward over-redaction.** Key-name matching uses
substring matching, not whole-word - `token_endpoint` gets redacted as
a side effect of containing `token`, even though it's typically a URL.
A false positive here costs a harmless string disappearing from a
collected fact; a false negative lets a real secret reach a customer's
committed repository. The package's own doc comment states this
tradeoff explicitly, so a future contributor tightening the matching
"for precision" understands what they'd be trading away.

**Redaction happens inside each frontend's own `Parse`/`Collect`
function, not as a wrapper around `cmd/substrate`'s JSON writers.**
CLAUDE.md's own phrasing - "redact at collection" - is specific about
where, not just that it happens somewhere before disk. Doing it inside
each collector means every consumer downstream (the raw JSON, the IR
mapping, `compile`'s merged evidence graph) inherits the protection
automatically, including any future mapper that might otherwise capture
a raw value nobody thought to re-check.

**Kubernetes gets one Kind-aware rule beyond the generic two layers**:
a `kind: Secret` object's `data` and `stringData` fields are redacted
wholesale, unconditionally. `data` is not itself a secret-shaped key
name - a `ConfigMap` has one too, and that one is ordinary application
configuration this tool needs to evidence - so only
`internal/frontend/kubernetes` itself, which already knows the object's
`kind` at the point it decodes each document, can apply this correctly.
`internal/redact` stays generic and Kubernetes-unaware; the Kind check
lives in `kubernetes/parse.go`, calling `redact.Placeholder` directly
rather than `internal/redact` growing any notion of what a Kubernetes
Secret is.

**Terraform needed its own glue, not a direct call into `redact.Value`.**
`AttributeValue.Value` is documented (graph.go) as holding the same
shape `encoding/json` produces - `string`, `bool`, `float64`, `[]any`,
`map[string]any` - which `redact.Value` already handles directly. But a
*nested block's* `Value` actually holds `map[string]AttributeValue` or
`[]map[string]AttributeValue` instead (see `evalBody`, which the
existing doc comment doesn't mention - a small, pre-existing
documentation gap this ADR surfaces but doesn't fix, since fixing
`AttributeValue`'s own doc comment is unrelated to redaction).
`internal/frontend/terraform/redact.go`'s `redactAttributes`/
`redactAttributeValue` walk that second shape directly and delegate to
`redact.KeyLooksSecret`/`redact.String`/`redact.Value` for everything
else - `internal/redact` itself stays unaware that `AttributeValue`
exists, the same boundary discipline as the Kubernetes case above.

**AWS S3/IAM collectors get exactly one integration point, in
`provenance.go`'s shared `unresolvedRecord`.** Neither collector
gathers raw secret material to begin with - S3's collected fields are
an encryption algorithm name and four booleans; IAM's are a boolean, a
device count, and key ages, never key material itself - so the only
place arbitrary, uncontrolled text reaches a `provenance.Record` at all
is `UnresolvedReason`, built from a raw AWS SDK `err.Error()`. AWS API
errors aren't documented to ever echo customer secrets, but redacting
that one text field, at the one function both collectors already route
every failure through, is a cheap, complete defense-in-depth pass
rather than something that needed threading through either collector
file individually.

## Post-review fixes

`/code-review` found two real gaps in the first pass, both fixed with
regression tests verified against the pre-fix code:

- Terraform's `AttributeValue.Unresolved` field was copied verbatim in
  `redactAttributeValue`, exempt from the content-pattern layer every
  other string leaf gets. Most `Unresolved` reasons are this package's
  own fixed diagnostic text, but `evalAttribute`'s "could not evaluate
  expression: %s" case embeds an hcl diagnostic's own `Error()` string
  - not guaranteed never to echo source content back. Fixed by routing
    `Unresolved` through `redact.String` uniformly across every branch.
- Kubernetes' Secret redaction only wiped the top-level `data`/
  `stringData` fields. `kubectl apply` writes the object's entire prior
  manifest into `metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]`
  as one JSON string on every apply - including a Secret's own base64
  data - and the generic key-name/content pass doesn't parse a string
  that happens to itself be JSON, so that annotation carried an
  unredacted snapshot of exactly what the Kind-aware rule two lines
  above had just redacted. Fixed with its own unconditional (any Kind)
  rule, documented in `docs/redaction-coverage.md`.

## Consequences

Positive. FR-4.4/FR-4.5 are now real, not aspirational. Every frontend
has a passing regression test proving redaction actually fires on a
realistic secret-shaped fixture (a hardcoded `db_password` in Terraform,
a `kind: Secret`'s `data` field in Kubernetes, a hardcoded token in a
GitHub Actions workflow's `env`), each verified to fail against the
pre-wiring code before this change, per the project's own testing
discipline.

Negative. Pattern-based redaction is fundamentally incomplete, disclosed
rather than hidden in `docs/redaction-coverage.md`. A secret with an
unrecognizable shape and a non-obvious key name is real, uncaught risk
that persists until a customer's own review process (or a future,
narrower pattern addition) catches it - this package reduces that risk
substantially, it does not eliminate it, and nothing in its design
should be read as claiming otherwise.

Open. `secretKeyNames` and `contentPatterns` are both starting lists,
expected to grow as real customer data surfaces shapes not yet covered.
Whether PII patterns (email, phone, SSN) are ever worth adding depends
on whether a future collector (Okta, in particular - user directory
data is exactly where PII concentrates) actually surfaces that kind of
data; nothing collected today does.
