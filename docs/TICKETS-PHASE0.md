# Phase 0 tickets

Ordered. Each is scoped to be a single Claude Code session or less. Every ticket states its definition of done, because "build rules ingestion" is not a task an agent can verify it finished.

Legend: `[eng]` engineering, `[analysis]` desk research, `[ops]` non-engineering but blocking.

---

## T-001 `[analysis]` Crosswalk analysis

Gates everything. Do it first or in parallel with T-002, not after.

Take at least 40 requirements spanning FedRAMP 20x KSIs, NIST 800-171, and PCI DSS 4.0. Cover at least four 800-53 families. Deliberately include hard cases: log retention, encryption key management, network segmentation, personnel screening, security training.

For each requirement record: 800-53 family, the specific evidence artifact each framework expects, granularity demanded, assessment cadence, who accepts it.

Then compute overlap at the artifact level. The question is "does the same collected fact satisfy both," not "do both mention encryption."

Done when: `docs/crosswalk-analysis.md` exists with a spreadsheet or table, a single overlap percentage, worked examples of three matches and three mismatches, and an explicit go/no-go recommendation against the gate in REQUIREMENTS.md section 16.1.

---

## T-002 `[eng]` Vendor and checksum the rules dataset

Covered by SETUP.md step 7, but tracked here so it is not skipped.

Done when: `internal/rules/data/` contains the JSON, the schema, and `CHECKSUMS.txt`, all committed, and the dataset version is recorded in the commit message.

---

## T-003 `[eng]` Typed model of the rules dataset

Implements FR-1.1.

Read `AGENTS.md` from the FedRAMP rules repo first.

Model Definitions (FRD), Rules (FRR), and Key Security Indicators (KSI) as Go types in `internal/rules`. Prefer explicit structs over `map[string]any`. Unknown fields should be preserved, not dropped, so a dataset update does not silently lose data.

Done when: the vendored dataset round-trips through the model without loss, tests prove it, `make boundaries` and `make test` pass.

---

## T-004 `[eng]` Schema validation

Implements FR-1.2.

Validate the dataset against its published JSON schema on load. Fail loudly with a useful message on drift. A schema mismatch is not a warning.

Done when: a test loads the real dataset and passes, and a second test with a deliberately corrupted fixture fails with a clear error naming the offending path.

---

## T-005 `[eng]` Rules query command

Implements FR-1.5.

`substrate rules show --class C` and variants by certification type and path.

Done when: output is accurate against the dataset, spot-checked by hand against fedramp.gov for at least five rules, and the command has a golden test.

---

## T-006 `[analysis]` Derive authoritative rule and KSI counts

We currently carry numbers from vendor blogs. Replace them with numbers from the dataset.

Done when: `docs/rule-counts.md` records counts per class and per ruleset, derived programmatically, with the dataset version stated. Then correct the strategy documents.

---

## T-007 `[eng]` Ruleset differ

Implements FR-1.4. Small work now, major product capability later, since ruleset migration is a retention mechanism.

`substrate rules diff <versionA> <versionB>` producing structured added, removed, and modified records.

Done when: diffing the vendored version against a synthetically modified copy produces correct structured output, with tests.

---

## T-008 `[eng]` Golden-file test harness

Before any parser. This is the regression net.

A harness that walks `testdata/fixtures/*/`, runs the pipeline, and compares against `expected/`. Must support deliberate regeneration via an env var or flag, and must refuse to regenerate silently.

Done when: `make golden` runs against at least the `minimal` fixture and fails loudly when expected output differs.

---

## T-009 `[eng]` Reproducibility proof

The CI job exists in the scaffold but cannot pass until `compile` produces output.

Once T-008 lands, make `scripts/check-reproducible.sh` meaningful: stable map iteration, sorted keys, no wall-clock time in artifacts.

Done when: `make repro` passes and a deliberately introduced timestamp in output makes it fail.

---

## T-010 `[eng]` IR skeleton

Define the evidence graph types in `internal/ir`: node, edge, provenance, declared-vs-observed, confidence classification, schema version.

Do not implement mapping logic yet. This is the data model only.

Done when: types exist, serialize to stable JSON Lines, round-trip in tests, and `scripts/check-boundaries.sh` confirms no framework vocabulary leaked in.

---

## T-011 `[ops]` Read every applicable Class A rule

Not the summary pages. Every rule in CR26 that applies to 20x Class A.

Done when: `docs/class-a-checklist.md` lists each applicable rule, what it requires of us, and whether we currently satisfy it.

---

## T-012 `[ops]` SOC 2 Type II engagement

Longest lead time in the plan. Start immediately.

Done when: a firm is engaged and the observation window has a start date.

---

## T-013 `[ops]` Ten discovery interviews

Five Rev5-certified providers facing 2027 deadlines. Three FedRAMP-recognized assessors. Two agency authorizing officials or staff.

Ask assessors above all: what artifact would make your annual IVV meaningfully cheaper?

Done when: `docs/discovery-synthesis.md` exists with direct quotes, not a summary, and a list of implications for the backend output format.

---

## T-014 `[ops]` FedRAMP partnership contact

NTC-0009 states FedRAMP will not build this tooling, expects industry to, and invites organizations supporting open source capabilities to reach out to pete@fedramp.gov. Approved organizations get linked from official documentation.

Done when: email sent, response logged.

---

## T-015 `[ops]` Class A subject decision

Decide what we eventually certify. Recommendation in REQUIREMENTS.md section 16.4 is the hosted control plane.

Done when: an ADR in `docs/adr/` records the decision and reasoning.

---

## Phase 0 exit checklist

- [ ] T-001 crosswalk complete with a number and a go/no-go
- [ ] T-003 through T-007 rules ingestion working
- [ ] T-006 authoritative counts replacing vendor numbers
- [ ] T-008 through T-010 foundations proven in CI
- [ ] T-012 SOC 2 observation window started
- [ ] T-013 ten interviews synthesized
- [ ] Legal gates cleared before Phase 1 parsers begin
