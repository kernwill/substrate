# Redaction coverage

FR-4.5: redaction is testable and its coverage documented. This file is
that document. Keep it in sync with `internal/redact/redact.go`'s own
doc comment - if the two ever disagree, the code is authoritative and
this file is stale.

Per CLAUDE.md's non-negotiable design principles: "Redact at collection.
Secrets, tokens, PII scrubbed before anything touches disk. Assume every
artifact gets committed to a customer repo." Every frontend collector
(Terraform, Kubernetes, GitHub Actions, and the AWS S3/IAM runtime
collectors) redacts before returning from its own `Parse`/`Collect`
function - not later, not as a wrapper around the JSON writer in
`cmd/substrate`. Everything downstream (the raw per-frontend JSON files,
the IR, `compile`'s merged evidence graph, `substrate collect`'s own
output) inherits that protection automatically.

## What is covered

### Key-name matching (`redact.KeyLooksSecret`)

A map key, resource attribute name, or workflow field name matching one
of the following fragments (case-insensitive substring match, not
whole-word) has its entire value replaced with `[REDACTED]`, regardless
of what the value actually contains:

```
password, passwd, secret, token, api_key, apikey, access_key,
accesskey, private_key, privatekey, client_secret, credential,
connection_string, bearer
```

Substring matching is deliberately broader than whole-word matching -
this project's own stated bias is toward over-redaction, not precision.
`token_endpoint` redacts as a side effect of containing `token`, even
though it's typically a URL, not a secret. That is accepted, not an
oversight.

### Content pattern matching (`redact.String`)

Independent of any key name, the following formats are redacted
wherever they appear in a string value:

- **PEM-encoded private key blocks** (`-----BEGIN ... PRIVATE KEY-----`
  through the matching `-----END ... PRIVATE KEY-----`, any of RSA, EC,
  OPENSSH, DSA, or unqualified).
- **AWS access key IDs** - the documented 4-letter type prefixes
  (`AKIA`, `ASIA`, `AIDA`, `AROA`, `AGPA`, `AIPA`, `ANPA`, `ANVA`,
  `APKA`) followed by 16 uppercase alphanumeric characters.
- **JWTs** - three base64url segments separated by dots, the first two
  starting with `ey` (base64 for `{"`).

This layer exists for exactly the case key-name matching misses: a
secret sitting under a field whose name gives no hint at all (a bare
`value`, say).

### Kind-aware wholesale redaction (Kubernetes only)

A Kubernetes object with `kind: Secret` has its entire `data` and
`stringData` fields replaced with `[REDACTED]` wholesale, regardless of
what any individual key inside them is named. This has to be a
Kind-aware rule, not a key-name one: `data` is not itself a secret-shaped
name (a `ConfigMap` has a `data` field too, and that one is ordinary,
non-secret application configuration this tool needs to evidence), so
only `internal/frontend/kubernetes`'s own `Parse` - which already knows
the object's `kind` - can apply it correctly.

A second, unconditional rule (any Kind, not just `Secret`) wholesale-
redacts `metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]`
when present: `kubectl apply` writes the object's entire prior manifest
into this annotation on every apply, re-serialized as one JSON string -
which would otherwise carry an unredacted snapshot of exactly the
fields the rule above just redacted, since the generic key-name/content
pass only recurses into real map/slice structure, never into a string
that happens to itself contain JSON text.

## Where it runs

| Frontend | Integration point | What's redacted |
|---|---|---|
| Terraform | `internal/frontend/terraform/redact.go`'s `redactAttributes`, called from `Parse` | Every resource attribute, including nested block attributes (`versioning_configuration { ... }` and similar) and each attribute's own `Unresolved` reason text |
| Kubernetes | `internal/frontend/kubernetes/parse.go`'s `parseFile` | The Secret-specific wholesale rule, the `last-applied-configuration` annotation rule, then every object's full decoded YAML |
| GitHub Actions | `internal/frontend/githubactions/parse.go`'s `Parse` | Every workflow's full decoded YAML |
| AWS S3 / IAM | `internal/frontend/collectors/aws/provenance.go`'s `unresolvedRecord` | Only `Provenance.UnresolvedReason` (built from a raw AWS SDK error string) - defense-in-depth, since neither collector collects raw secret material to begin with (S3's own fields are an encryption algorithm name and four booleans; IAM's are a boolean, a device count, and key ages - none of which are ever the secret itself) |

## What is NOT covered - disclosed, not hidden

Per `docs/REQUIREMENTS.md`'s own principle for coverage reporting
("publishing gaps builds more trust than hiding them, and assessors
will find them anyway"), applied here too:

- **A secret with a non-obvious key name and no recognizable content
  format is not caught.** A field named `value` or `data` holding a
  plain, unstructured password string (not an AWS key, not a JWT, not a
  PEM block) survives both layers. This is the fundamental limit of
  pattern-based redaction, not a bug to fix incrementally away - a
  human reviewing any customer-specific IaC for atypical secret shapes
  remains the real backstop.
- **AWS secret access keys** (the 40-character value paired with an
  access key ID) are not pattern-matched - a 40-character
  base64-alphabet string is indistinguishable from a great deal of
  legitimate, non-secret data (hashes, encoded identifiers), and a
  content pattern for it would carry an unacceptable false-positive
  rate. Access key IDs *are* covered (see above); secret access keys
  are not collected by this project's own AWS collectors in the first
  place, which is the actual mitigation here.
- **PII beyond what a JWT or the like might carry** - no email address,
  phone number, or SSN pattern exists yet. Infrastructure configuration
  (this project's actual input) rarely carries this kind of data
  directly; it is a real gap if that assumption turns out wrong for a
  future collector.
- **GitHub Actions and Terraform provider-native secret indirection**
  (`${{ secrets.X }}`, a Terraform variable marked `sensitive = true`)
  never reaches this codebase as a literal secret value in the first
  place - that's the reference, not the resolved value - so there is
  nothing to redact there. The risk this package guards against is
  specifically the case where an author bypasses that indirection and
  hardcodes a literal value instead.
