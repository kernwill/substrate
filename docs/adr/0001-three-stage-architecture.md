# ADR 0001: Three-stage compiler with a framework-agnostic IR

Date: 2026-07-30
Status: Accepted

## Context

Existing compliance products are built around a control library with evidence
attached. Adding a framework means adding a content library, so multi-framework
products are effectively N disconnected products behind one UI.

Our thesis is that most security frameworks reduce to the same technical
substrate: identity, encryption, logging, vulnerability management, change
control, backup, segmentation, asset inventory. If that is true, the evidence
can be collected once and projected into many frameworks.

## Decision

Three stages. Front end parses and collects, producing raw facts with
provenance. The IR normalizes facts into an evidence graph keyed on NIST 800-53
control families. Back ends map the IR to specific frameworks and emit their
artifacts.

The IR is framework-agnostic and enforced as such: no imports from backends, and
no framework vocabulary in the package. Enforced in CI, not by convention.

800-53 was chosen as the IR key because it is the hub most US frameworks
crosswalk to.

## Consequences

Positive. The second backend should cost weeks rather than quarters. That
economic claim is the whole scaling argument.

Negative. More indirection than a FedRAMP-only tool needs, and the IR must be
designed for frameworks we have not built yet, which risks over-generalizing
against imagined requirements.

Unproven. Whether artifact-level overlap between frameworks is actually high
enough. Ticket T-001 tests this before we build on it, and Phase 4 measures it
for real by shipping CMMC and recording the effort split.

If Phase 4 shows backend two required significant front-end changes, this ADR
should be revisited and the company scope reduced accordingly.
