# ADR 0002: JSON Schema validation via a real validator, with an ECMA-262 regex engine

Date: 2026-09-08
Status: Accepted

## Context

FR-1.2 requires validating the vendored FedRAMP Consolidated Rules dataset
against its published JSON Schema and failing loudly on drift. Hand-rolling
that validation (walking the schema's `$defs`, `oneOf`/`allOf`, `patternProperties`,
`propertyNames`, `dependentRequired`, etc.) would be reinventing a rule engine,
which this project already declines to do for policy evaluation (OPA is
embedded instead of a bespoke engine). The same reasoning applies here.

`github.com/santhosh-tekuri/jsonschema` is a mature, spec-compliant Draft
2020-12 implementation. Its v5 line uses Go's standard `regexp` (RE2) to
compile every schema `pattern`. The vendored schema's `frr_requirement_id`
pattern is `^(?!KSI-)[A-Z]{3}-[A-Z]{3}-[A-Z0-9]{3}$` - a negative lookahead
disambiguating FRR IDs from KSI IDs that happen to share the same shape.
Negative lookahead is valid ECMA-262 (the regex dialect JSON Schema
specifies) but RE2 deliberately excludes lookaround to guarantee linear-time
matching, so v5 fails to compile our own unmodified, checksummed schema.

The schema is vendored and checksummed (`internal/rules/data/CHECKSUMS.txt`);
patching it to avoid the lookahead was rejected as an option, matching the
project's stance on not hand-editing golden/vendored artifacts to make a
tool happy.

## Decision

Use `jsonschema/v6`, which added a pluggable regex engine
(`Compiler.UseRegexpEngine`), and back it with
`github.com/dlclark/regexp2` in ECMAScript mode - a full ECMA-262 engine
that supports lookaround. This validates the dataset's `pattern` keywords
(including the KSI/FRR disambiguation) exactly as FedRAMP's own schema
author intended, without modifying the vendored files.

## Consequences

Positive. Schema drift detection is real JSON Schema Draft 2020-12
conformance, not a partial reimplementation, and it will keep working as
the upstream schema evolves (new `$defs`, patterns, conditionals) without
us tracking every keyword by hand.

Negative. Two more third-party dependencies
(`santhosh-tekuri/jsonschema/v6`, `dlclark/regexp2`, pulling in
`golang.org/x/text` transitively) that will show up in the SBOM and in a
customer's dependency review. Both are narrowly scoped (schema validation,
regex), pure Go, and widely used.

Unproven. Whether the upstream FedRAMP schema will introduce further
ECMA-262-only regex features (backreferences, etc.) that regexp2 also
can't represent identically to a browser/Node ECMA engine's edge-case
behavior. No evidence of this today; revisit if a future schema pull
fails validation for a similarly exotic reason.
