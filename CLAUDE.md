# CLAUDE.md

Operational context for Claude Code. Read this before doing anything in this repo.

Full requirements live in `docs/REQUIREMENTS.md`. This file is the short version you need every session.

---

## What this is

A compliance compiler. It reads a customer's infrastructure-as-code, cluster manifests, CI configuration, identity policy, and cloud control plane; normalizes what it finds into an evidence graph keyed on NIST 800-53 control families; and emits regulatory artifacts from that graph. It runs in CI and fails the build when a mapped control regresses.

First target framework is FedRAMP 20x under the Consolidated Rules for 2026 (CR26). It is the first backend, not the definition of the product.

The thesis: compliance artifacts should be compiled from infrastructure, not authored alongside it, and compiled from one framework-agnostic intermediate representation rather than one pipeline per framework.

---

## Architecture: three stages

```
frontend  ->  ir  ->  backends
(parse)     (IR)     (emit)
```

| Stage | Package | Responsibility | Framework-aware |
|---|---|---|---|
| Front end | `internal/frontend` | Parse and collect. Produce raw facts with provenance. | No |
| IR | `internal/ir` | Normalized evidence graph keyed on 800-53. | No |
| Back end | `internal/backends` | Map IR to a framework. Emit its artifacts. | Yes |

---

## Architectural invariants

These are not style preferences. Violating them destroys the product thesis. `scripts/check-boundaries.sh` enforces them in CI and runs first.

1. `internal/frontend` MUST NOT import `internal/backends`.
2. `internal/ir` MUST NOT import `internal/backends` or `internal/frontend`.
3. No framework vocabulary in `internal/ir`. The words KSI, FedRAMP, CMMC, PCI must not appear there. If you need them, you are in the wrong package.
4. Adding a framework must not require changes to frontend or ir. If it does, that is a leak. Do not paper over it, record it in `docs/adr/` because measuring those leaks is the central experiment of this project.

If a task seems to require breaking one of these, stop and say so rather than relaxing the check. Moving code is the fix; loosening the boundary never is.

---

## Non-negotiable design principles

Deterministic core, AI at the edges. No LLM output may enter the evidence graph or a certification artifact without a deterministic check or a recorded human approval. We produce attestations to the federal government. A hallucinated control implementation is a fraud exposure, not a bug. The core must run fully with the AI layer absent.

Provenance on every fact. Source type, locator (file and line, or API and parameters), timestamp, collector version, and whether the fact is Declared (from config) or Observed (from runtime). Declared versus Observed is a first-class field because CR26 separates evidence of implementation from evidence of effectiveness and demands both.

Reproducibility. Same inputs plus same engine version equals byte-identical output. Sorted keys, no wall-clock time in artifacts, no map iteration order dependence. `make repro` proves it.

Fail visible, never fail silent. Rule states are `satisfied`, `not_satisfied`, `undetermined`, `not_applicable`. Undetermined carries a reason. Never collapse undetermined into either satisfied or not_satisfied. Absence of evidence is not evidence of compliance.

Read-only always. The AWS role we require is read-only and its policy is published. Never write code that mutates customer infrastructure.

No telemetry. Not opt-out, absent. Our buyers are FedRAMP providers; silent phone-home is disqualifying.

Redact at collection. Secrets, tokens, PII scrubbed before anything touches disk. Assume every artifact gets committed to a customer repo.

---

## Stack

| Concern | Choice | Notes |
|---|---|---|
| Core, IR, CLI | Go 1.27 | Single static binary is the whole distribution story for a CI tool |
| HCL / Terraform | `hashicorp/hcl` | Native |
| Kubernetes | `client-go`, Helm SDK for rendering | |
| Rule evaluation | Open Policy Agent embedded as a library, rules in Rego under `rego/` | Do not write a bespoke rule engine |
| Local persistence | JSON Lines artifacts, SQLite for indexing | Diffable, greppable, no server |
| Framework rulesets | Vendored JSON from `github.com/FedRAMP/rules`, pinned and checksummed | |
| AI layer | Separate Python service, out of process, invoked explicitly | Keeps the deterministic-core rule structural rather than aspirational |

Do not add dependencies casually. Every dependency is something a customer's security review will ask about and something that appears in our own SBOM.

---

## Commands

```
make check       # everything CI runs. Run before every commit.
make boundaries  # architectural invariant check
make lint        # golangci-lint
make test        # go test ./... -race
make build       # -> bin/substrate
make repro       # byte-identical output check
make golden      # golden-file tests only
```

CLI exit codes: `0` pass, `1` rule regression (CI gate failure), `2` usage or internal error. The gate depends on this distinction, do not collapse them.

---

## Planned CLI surface

```
substrate rules show   --class C
substrate rules diff   <versionA> <versionB>
substrate collect      --source <dir>
substrate compile      --source <dir> --out <dir>
substrate ir query     --control AC-2
substrate gate         --baseline <file>
substrate baseline update
```

---

## Phase 1 scope discipline

Team is 2 to 3 engineers. Breadth kills. Phase 1 targets exactly one configuration:

- Cloud: AWS only, including GovCloud partition
- IaC: Terraform only
- Orchestrator: Kubernetes via manifests or Helm
- CI: GitHub Actions
- Identity: Okta plus AWS IAM

If asked to add Azure, GCP, Pulumi, CloudFormation, CDK, or Ansible, push back and cite this section. Say no now, revisit in Phase 2.

Also out of scope until later phases: any UI, any hosted service, multi-tenancy, user accounts, agentic remediation, any second framework backend.

Never build: a vulnerability scanner (ingest only), a generic GRC platform, a DOCX or XLSX exporter (CR26 retires both formats).

---

## Domain vocabulary

| Term | Meaning |
|---|---|
| CR26 | FedRAMP Consolidated Rules for 2026, published 2026-06-24, valid through 2028-12-31 |
| KSI | Key Security Indicator. Ten families. Replaces narrative controls in 20x. |
| SDR | Security Decision Record. Replaces the SSP. A persistently maintained record with history, not a document. |
| CPO | Certification Package Overview |
| SCG | Secure Configuration Guide |
| SCN | Significant Change Notification. Derived from IR diffs. |
| VER | Vulnerability Evaluation and Reporting |
| CCM | Collaborative Continuous Monitoring |
| IVV | Independent Verification and Validation |
| Class A/B/C/D | Certification classes. Replaced Low/Moderate/High. A is new pilot tier, B was Low, C was Moderate, D is High. |
| Verification | Evidence that a control is implemented (Declared) |
| Validation | Evidence that a control is effective (Observed) |

---

## Working style in this repo

Small, verifiable changes. Every PR should leave `make check` green.

Write the golden fixture before the parser. Fixtures are the regression net and they are more valuable than the code they test.

When something is undetermined, say so in the output rather than guessing. That instruction applies to you as much as to the compiler: if a requirement here is ambiguous, ask rather than inventing an interpretation, because an invented interpretation in a compliance product becomes an incorrect attestation.

Record architectural decisions in `docs/adr/` as short numbered markdown files. Especially record anything that felt like it wanted to break an invariant.

Do not edit `expected/` golden files by hand to make a test pass. Regenerate deliberately and review the diff, because that diff is a change in what we assert to the federal government.
