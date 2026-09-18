// Package dockerfile extracts base image references from Dockerfiles
// for supply chain evidence (FR-2.7, SHOULD priority).
//
// Scope is deliberately narrow: only FROM instructions are parsed - not
// RUN, COPY, USER, or any other instruction. FR-2.7's own text is
// "Dockerfile and base image extraction for supply chain evidence," and
// container hardening concerns like non-root users are already this
// project's Kubernetes frontend's job at the pod/container spec level
// (internal/frontend/kubernetes's container/pod security context
// mapping) - duplicating that here would be a second, weaker source of
// truth for the same underlying control, not new evidence.
//
// # What "base image extraction" means here
//
// Each FROM instruction is classified into exactly one of three kinds
// (BaseImageKind):
//
//   - external: a real, externally-sourced image reference
//     (repository[:tag][@digest]). Whether it is pinned to an immutable
//     digest or only a mutable tag (or no tag at all, which the Docker
//     CLI treats as ":latest") is the fact this package's IR mapper
//     evidences - see ir.go.
//   - scratch: FROM scratch, the literal empty base image. There is no
//     external component here to authenticate at all.
//   - local_stage: FROM <name>, where name matches an earlier stage's
//     "AS <name>" in the same file. This is a reference to this
//     project's OWN build output, not a pulled external artifact.
//
// scratch and local_stage are real, resolved (Deterministic) facts, not
// unresolved ones - this package knows exactly what they are. They
// simply produce no IR node, the same "collected but not applicable to
// this control" treatment internal/frontend/collectors/aws's Bucket.Logging
// field gets before any reviewed control assignment exists for it,
// except here the reason is that the control (supply-chain component
// authenticity) genuinely does not apply, not that no mapping has been
// reviewed yet.
//
// A FROM instruction whose image argument contains an unexpanded build
// argument or variable (e.g. "FROM ${BASE_IMAGE}") is genuinely
// unresolved (Provenance.Confidence = provenance.Unresolved) - this
// package does not track ARG declarations or perform variable
// substitution, matching FR-2.3's "never guess" principle applied here
// rather than to Terraform's HCL expressions.
package dockerfile
