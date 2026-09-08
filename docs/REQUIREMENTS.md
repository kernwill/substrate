# Substrate: End-to-End Requirements

Version 1.0, July 30, 2026

This is the complete requirements document. It supersedes the earlier `compliance-compiler-requirements.md` and folds in the strategy context needed to make decisions without reading the strategy memo.

Tags: `[MUST]` required for the phase. `[SHOULD]` do if capacity allows. `[WON'T]` explicitly out of scope, listed so it stops being relitigated.

Confidence tags on factual claims: `[verified]` confirmed against a fedramp.gov primary source. `[dataset-verified]` confirmed programmatically against the vendored `fedramp-consolidated-rules.json` itself (also a fedramp.gov primary source, but checked by our own tooling rather than a human reading a page) - see `docs/rule-counts.md` for the derivation and the test that keeps it from going stale. `[reported]` secondary source only. `[inference]` reasoning from verified facts.

---

# Part I: Context

## 1. Problem statement

Compliance evidence today is authored. Someone writes a narrative describing how a control is implemented, attaches a screenshot, and an assessor reads it once a year. The underlying infrastructure changes daily; the documentation does not.

FedRAMP's Consolidated Rules for 2026 (CR26), published June 24, 2026 and valid through December 31, 2028, changed what is being asked for. `[verified]` The deliverable is now a persistently maintained Security Decision Record, continuously validated Key Security Indicators, and machine-readable ongoing reports. The rules themselves ship as versioned JSON in a public repository with a guide for AI agents consuming them. `[verified]`

The source material for all of this already exists in the customer's Terraform, Kubernetes manifests, CI configuration, identity provider policy, and cloud control plane. Nobody is compiling it.

## 2. Product definition

A compiler with three stages, the middle of which is framework-agnostic.

```
Front end                    Intermediate representation        Back ends
─────────                    ───────────────────────────        ─────────
Terraform / Pulumi / CFN                                   →   FedRAMP 20x (CPO/SCG/SDR)
Kubernetes manifests                                       →   CMMC / NIST 800-171
CI/CD pipeline config    →   Normalized evidence graph     →   PCI DSS 4.0
IdP / SSO policy             keyed on NIST 800-53              SOC 2 Type II
Cloud control plane APIs     control families                  SOX ITGC
Ticketing / incident data    (Declared + Observed,          →   RMF / eMASS
Scanner + SBOM output         timestamped, provenanced)     →   DORA / NIS2 / ISO 27001
                                       ↓
                              CI gate: build fails when any
                              mapped control regresses
```

The front end is expensive and written once. The IR is the moat. Back ends are mappings plus a serializer, and after the first two should be measured in weeks.

## 3. Why FedRAMP 20x is backend one

Decision locked. Reasoning preserved so it is not casually reopened.

- The buyer is a commercial company, not a government program office. Repeatable with one sales motion, no sponsor or contract vehicle required.
- The spec is public, versioned, and machine-readable. No other framework hands us a formal grammar for free.
- 500+ existing certified providers face dated mandatory migration through 2027. `[verified]`
- Certification is self-initiated on the Program path. No agency sponsor required for Class A, B, or C. `[verified]`

RMF and eMASS would be the alternative if a government anchor customer were certain. It is not, and FedRAMP-first costs almost nothing if one appears, since both sit directly on 800-53. `[inference]`

## 4. Market timing

| Date | Event | Status |
|---|---|---|
| 2026-06-24 | CR26 published | `[verified]` |
| 2026-07-04 | Optional early adoption begins | `[verified]` |
| 2026-07-28 | FedRAMP Ready retired | `[verified]` |
| 2026-08-03 | 20x Class A pipeline opens | `[verified]` |
| 2026-08-31 | 20x Class B and C pipeline opens | `[verified]` |
| 2027-01-01 | CR26 mandatory for all stakeholders | `[verified]` |
| 2027-01-01 | Significant Change Notifications mandatory | `[verified]` |
| 2027-04-02 | Collaborative Continuous Monitoring mandatory | `[verified]` |
| 2027-06-01 | Vulnerability Detection and Response mandatory | `[verified]` |
| 2027-06-11 | No new Rev5 certifications accepted | `[verified]` |
| 2027-08-01 | Authorization Data Sharing mandatory, Connect.gov retired | `[verified]` |
| 2027-11-01 | Class A/B/C semi-structured text; Class D full machine-readable | `[verified]` |

Those 2027 dates are the Phase 2 sales pitch. Name them explicitly in the product.

## 5. What CR26 requires that matters to us

Package artifacts under 20x, 17 rules across three rulesets. `[dataset-verified]`

| Artifact | Rules | Replaces |
|---|---|---|
| Certification Package Overview (CPO) | 4 | Base System Security Plan |
| Secure Configuration Guide (SCG) | 9 | Customer responsibility matrix |
| Security Decision Record (SDR) | 4 | The SSP itself |

The SDR is described as "a persistently maintained, verified, and validated record of the security decisions made by the cloud service provider over the lifecycle of their cloud service offering." `[verified]` That is a data model requirement. Model it as an append-only decision log with current-state projection, not a generated document.

Assurance rulesets, 76 rules across six. `[dataset-verified]`

| Ruleset | Rules |
|---|---|
| Vulnerability Evaluation and Reporting (VER) | 19 |
| Collaborative Continuous Monitoring (CCM) | 17 |
| Significant Change Notification (SCN) | 16 |
| Independent Verification and Validation (IVV) | 9 |
| Addressing FedRAMP Communication (AFC) | 8 |
| Incident Evaluation and Communication (IEC) | 7 |

Ninety-three of the rules govern the package and ongoing assurance. `[dataset-verified]` The recurring obligation is the bulk of the regime, which is the structural argument for recurring revenue.

See `docs/rule-counts.md` for the derivation of every count on this page and the rest of the dataset (definitions, KSI indicators, control entries) - it also carries the test that fails the build if these drift from what the vendored dataset actually contains.

Two IVV rules define our product in the government's own words: `[verified]`

- IVV-CSO-SEI, evidence of implementation, "preferably by allowing them to see how firewall configurations are deployed from a source of truth."
- IVV-CSO-SEE, evidence of effectiveness, validating that the thing actually works.

And IVV-CSO-USR: "Many modern cloud services using effective automation do not need to use representative sampling and are capable of persistently verifying and validating the majority of their security measures automatically." `[verified]`

Ten KSI families: change management, cloud native architecture, cybersecurity education, identity and access management, incident response, monitoring/logging/auditing, policy and inventory, recovery planning, service configuration, supply chain risk. `[dataset-verified]`

Certification classes replaced impact levels. `[verified]`

| Class | Replaces | Sponsor required (20x) | Independent assessment |
|---|---|---|---|
| A | New pilot tier | No | MAY, annually |
| B | Li-SaaS and Low | No | MUST, annually |
| C | Moderate | No | MUST, annually |
| D | High | 20x coming 2027 | MUST, annually |

---

# Part II: Functional requirements

## 6. FR-1: Rules ingestion

| ID | Requirement | Priority |
|---|---|---|
| FR-1.1 | Parse `fedramp-consolidated-rules.json` into a typed Go model covering Definitions (FRD), Rules (FRR), and Key Security Indicators (KSI) | MUST |
| FR-1.2 | Validate against the published JSON schema; fail loudly on drift | MUST |
| FR-1.3 | Pin dataset version; record it in every compiler output | MUST |
| FR-1.4 | Diff two dataset versions into structured added/removed/modified records | MUST |
| FR-1.5 | Query applicable rules by certification class, type, and path | MUST |
| FR-1.6 | Watch upstream repo and alert on dataset change | SHOULD |

Read `AGENTS.md` in `github.com/FedRAMP/rules` before implementing. It states how the program office expects machines to consume the dataset.

Intended for open source release under Apache 2.0. Keep proprietary logic out.

## 7. FR-2: Front end, static parsing

| ID | Requirement | Priority |
|---|---|---|
| FR-2.1 | Terraform: parse HCL, resolve modules and variables where statically determinable, produce a resource graph | MUST |
| FR-2.2 | Terraform: read remote state where permitted; never require it | MUST |
| FR-2.3 | Terraform: emit `unresolved` with a reason where a value cannot be statically determined. Never guess | MUST |
| FR-2.4 | Kubernetes: parse manifests; render Helm with supplied values | MUST |
| FR-2.5 | Kubernetes: extract network policies, RBAC bindings, pod security context, secret references, admission config | MUST |
| FR-2.6 | GitHub Actions: extract required reviews, branch protection, deployment approvals, secret scanning, dependency review | MUST |
| FR-2.7 | Dockerfile and base image extraction for supply chain evidence | SHOULD |

## 8. FR-3: Front end, runtime collection

This is the evidence-of-effectiveness half (IVV-CSO-SEE).

| ID | Requirement | Priority |
|---|---|---|
| FR-3.1 | AWS IAM: users, roles, policies, MFA status, access key age | MUST |
| FR-3.2 | AWS CloudTrail: configuration, retention, log file integrity validation | MUST |
| FR-3.3 | AWS KMS: key policies, rotation status | MUST |
| FR-3.4 | AWS VPC and security groups: topology, ingress and egress rules | MUST |
| FR-3.5 | AWS S3: encryption, public access block, access logging | MUST |
| FR-3.6 | AWS Config, GuardDuty, Security Hub: enablement and findings | MUST |
| FR-3.7 | Operate under a strictly read-only IAM role; publish that policy document | MUST |
| FR-3.8 | Support the GovCloud partition | MUST |
| FR-3.9 | Okta: MFA enforcement, session policy, provisioning and deprovisioning events, admin role assignments | MUST |
| FR-3.10 | Collectors individually runnable and testable against recorded fixtures; no live cloud dependency in unit tests | MUST |
| FR-3.11 | Vulnerability scanner ingestion, normalized | SHOULD |
| FR-3.12 | SBOM ingestion, CycloneDX or SPDX | SHOULD |

## 9. FR-4: Provenance and redaction

| ID | Requirement | Priority |
|---|---|---|
| FR-4.1 | Every fact records: source type, locator (path and line, or API and parameters), timestamp, collector version | MUST |
| FR-4.2 | Every fact tagged `declared` or `observed` as a first-class field | MUST |
| FR-4.3 | Every fact carries confidence: `deterministic`, `heuristic`, or `unresolved` | MUST |
| FR-4.4 | Redaction of secrets, tokens, and PII occurs at collection, before any disk write | MUST |
| FR-4.5 | Redaction is testable and its coverage documented | MUST |
| FR-4.6 | Full derivation chain queryable for any assertion | MUST |

## 10. FR-5: Intermediate representation

| ID | Requirement | Priority |
|---|---|---|
| FR-5.1 | Typed evidence graph; nodes are facts, edges are relationships | MUST |
| FR-5.2 | Nodes keyed to NIST 800-53 control families, enumerated where unambiguous | MUST |
| FR-5.3 | Serializable to JSON Lines with stable ordering and byte reproducibility | MUST |
| FR-5.4 | Versioned schema with a migration path; old artifacts remain readable | MUST |
| FR-5.5 | Queryable: `substrate ir query --control AC-2` returns all bearing facts with provenance | MUST |
| FR-5.6 | Contains zero framework-specific vocabulary | MUST |
| FR-5.7 | Snapshot retention for trend and drift analysis | SHOULD |

## 11. FR-6: FedRAMP 20x backend

| ID | Requirement | Priority |
|---|---|---|
| FR-6.1 | Mapping from IR nodes to FRR rules and KSIs, expressed in Rego, one module per KSI family with tests | MUST |
| FR-6.2 | Emit Certification Package Overview | MUST |
| FR-6.3 | Emit Secure Configuration Guide | MUST |
| FR-6.4 | Emit Security Decision Record as an append-only log with current-state projection | MUST |
| FR-6.5 | Machine-readable primary output; human-readable generated from it | MUST |
| FR-6.6 | Per-rule status: `satisfied`, `not_satisfied`, `undetermined`, `not_applicable`. Undetermined carries a reason and a remediation hint | MUST |
| FR-6.7 | Coverage report: automated vs human-attested vs not visible | MUST |
| FR-6.8 | Draft narrative generation for human-attested items, marked draft, requiring explicit approval | SHOULD |
| FR-6.9 | No DOCX or XLSX output, ever. CR26 retires both formats `[verified]` | WON'T |

## 12. FR-7: CI gate

| ID | Requirement | Priority |
|---|---|---|
| FR-7.1 | GitHub Action runs the compiler on pull requests | MUST |
| FR-7.2 | Diff resulting posture against the main branch baseline | MUST |
| FR-7.3 | Fail the check when a previously satisfied rule regresses | MUST |
| FR-7.4 | PR comment naming the rule, the file and line, and the prior state | MUST |
| FR-7.5 | Configurable severity policy including warn-only mode | MUST |
| FR-7.6 | `substrate baseline update` with an approval trail recorded in the SDR | MUST |
| FR-7.7 | GitLab CI support | SHOULD |

## 13. FR-8: Continuous assurance

| ID | Requirement | Priority |
|---|---|---|
| FR-8.1 | Derive candidate significant changes from IR diffs between commits | MUST |
| FR-8.2 | Classify against SCN ruleset categories, traceable to the triggering IR delta | MUST |
| FR-8.3 | Emit SCN artifacts machine-readable | MUST |
| FR-8.4 | Human approval gate before anything is marked notified. Never auto-notify a federal customer | MUST |
| FR-8.5 | Pre-merge preview: "this PR would constitute a significant change of category X" | SHOULD |
| FR-8.6 | Normalize scanner findings into the IR with asset linkage | MUST |
| FR-8.7 | Implement VER impact determination logic | MUST |
| FR-8.8 | Track remediation timelines and deadline posture | MUST |
| FR-8.9 | Scheduled KSI revalidation independent of pull requests | MUST |
| FR-8.10 | Historical posture retention with trend output | MUST |
| FR-8.11 | Agency-consumable export structured for eventual API consumption | MUST |
| FR-8.12 | Ruleset migration: report affected artifacts on version bump, re-emit automatically | MUST |
| FR-8.13 | Migration playbooks for the five mandatory Rev5 transitions with 2027 deadlines | SHOULD |

## 14. FR-9: AI layer

Introduced in Phase 2, never before. The deterministic core must work first.

| ID | Requirement | Priority |
|---|---|---|
| FR-9.1 | Repository comprehension agent proposes IR mappings for unfamiliar infrastructure, with cited evidence | MUST |
| FR-9.2 | Every agent proposal requires explicit human acceptance, recorded with who and when | MUST |
| FR-9.3 | Agent runs out of process; core functions fully without it | MUST |
| FR-9.4 | Evaluation harness with labeled fixtures and tracked precision and recall | MUST |
| FR-9.5 | Remediation PR generation against customer IaC in their idiom | SHOULD |
| FR-9.6 | Assessor-facing narration explaining why telemetry satisfies a rule | SHOULD |
| FR-9.7 | No AI-authored content enters an artifact without deterministic check or recorded approval | MUST |

---

# Part III: Non-functional requirements

## 15. NFR

| ID | Requirement |
|---|---|
| NFR-1 | Single static binary, no runtime dependencies |
| NFR-2 | Runs in air-gapped and GovCloud environments with no additional work |
| NFR-3 | Byte-identical output for identical inputs and engine version |
| NFR-4 | Read-only access to all customer systems |
| NFR-5 | No telemetry. Absent, not opt-out |
| NFR-6 | Signed releases with published checksums and an SBOM, from the first tagged build |
| NFR-7 | Reproducible builds so a customer can verify our binary matches our source |
| NFR-8 | Published vulnerability disclosure policy from first public release |
| NFR-9 | Full compile of a mid-size repository completes within a CI-tolerable window; target under 5 minutes |
| NFR-10 | Exit codes: 0 pass, 1 rule regression, 2 usage or internal error |
| NFR-11 | Third-party penetration test before any hosted service goes live |

---

# Part IV: Phases

## 16. Phase 0: Validate the thesis, 6 to 8 weeks

The analysis can kill the plan. That is the point.

### 16.1 Crosswalk analysis `[MUST]`

The highest-value two weeks available. Everything downstream assumes framework overlap at the evidence level, which is currently an inference.

- Select at least 40 requirements spanning FedRAMP 20x KSIs, NIST 800-171, and PCI DSS 4.0. Include at least four 800-53 families and deliberately include hard cases (logging retention, key management, segmentation, personnel and training).
- For each: the 800-53 family, the evidence artifact each framework expects, granularity demanded, assessment cadence, and who accepts it.
- Compute overlap at the artifact level, not the control level. The question is "does the same collected fact satisfy both," not "do both mention encryption."
- Publish a written finding with a number and a recommendation.

Exit gate:

| Artifact-level overlap | Action |
|---|---|
| Below 60% | Stop. Rewrite the strategy before writing production code |
| 60 to 70% | Proceed, but design explicit per-framework extension points and expect backend two to cost more than advertised |
| Above 70% | Proceed with confidence |

### 16.2 Rules ingestion `[MUST]`

FR-1.1 through FR-1.5. Exit: `substrate rules show --class C` prints an accurate, schema-validated view, and `substrate rules diff` produces a usable changelog.

Replace every vendor-blog number in the strategy documents with numbers derived from the dataset.

### 16.3 Engineering foundations `[MUST]`

- Monorepo with enforced package boundaries, failing CI on violation
- Reproducible build proven by a CI job that runs twice and diffs
- Golden-file test harness, before the first parser
- Signed releases and SBOM from the first tagged build
- Documentation site scaffold `[SHOULD]`

### 16.4 Class A self-certification: decide the subject `[MUST]`

- Decide what we certify. Recommendation: the eventual hosted control plane. Certifying a hollow service to hold a badge will not survive assessor contact.
- Start SOC 2 Type II now regardless. It is the Class A prerequisite, needs a multi-month observation window, and is the longest pole in the entire plan.
- Confirm the true Class A minimum bar by reading every applicable CR26 rule, not summary pages. Produce a checklist.
- Determine whether Class A confers real agency purchasing legitimacy. Five conversations.
- Email `pete@fedramp.gov` regarding the industry partnership NTC-0009 invites `[SHOULD]`

### 16.5 Customer discovery `[MUST]`

Ten structured conversations: five Rev5-certified providers facing 2027 deadlines, three FedRAMP-recognized assessors, two agency authorizing officials or staff.

Ask assessors one question above all: what artifact would make your annual IVV meaningfully cheaper? Their answer should shape the backend output format more than our opinions.

Written synthesis with direct quotes, not a summary.

### 16.6 Phase 0 exit criteria

1. Crosswalk overlap documented with a number and a go/no-go
2. Rules ingestion working, counts derived from primary data
3. Repository foundations with boundary enforcement and reproducibility proven in CI
4. SOC 2 Type II engagement started
5. Ten discovery conversations completed and synthesized

### 16.7 Out of scope in Phase 0

`[WON'T]` Any UI. Any AI work. Any cloud collection. Any second framework beyond the crosswalk.

## 17. Phase 1: Compiler MVP, 4 to 5 months

Scope discipline. One configuration only: AWS including GovCloud, Terraform, Kubernetes, GitHub Actions, Okta plus AWS IAM. Say no to prospects on other stacks in this phase.

Implements FR-2 through FR-7.

### 17.1 Exit criteria

1. End-to-end run against a real design partner repository and AWS account, producing a complete 20x Class C package
2. A FedRAMP-recognized assessor reviews the output and states in writing what they would and would not accept. Schedule this before the code is finished
3. Coverage report shows at least 60% of applicable rules evidenced automatically
4. Reproducibility holds
5. CI gate running in at least one design partner pipeline

### 17.2 Out of scope in Phase 1

`[WON'T]` Azure, GCP, Pulumi, CloudFormation, CDK, Ansible. Hosted anything. Multi-tenancy or user accounts. Any second framework. Agentic remediation.

## 18. Phase 2: Continuous assurance, 3 to 4 months

Implements FR-8 and FR-9. This is where the recurring revenue lives, because CR26 put 76 of its rules in ongoing assurance.

### 18.1 Exit criteria

1. A design partner has run continuous assurance for a full quarter without manual intervention
2. At least one significant change detected, classified, approved, and notified through the tool
3. A ruleset version bump handled end to end
4. Onboarding agent measured: time from repository access to draft mapping, with accuracy numbers
5. First paying customer

## 19. Phase 3: Hosted control plane, 4 to 6 months, year two

Start only after Phase 2 has a paying customer.

Architecture constraint and the whole point: the hosted plane receives normalized findings pushed by the customer's CLI. Never credentials, never raw source, never collection on our infrastructure.

| ID | Requirement | Priority |
|---|---|---|
| FR-10.1 | Findings ingestion API with schema validation and version negotiation | MUST |
| FR-10.2 | Multi-tenant isolation with tenant-scoped encryption | MUST |
| FR-10.3 | Posture dashboard: current state, trends, coverage, drift | MUST |
| FR-10.4 | Multi-service view (CR26 pushes Class D toward per-service materials) | MUST |
| FR-10.5 | Assessor workspace, free. Trace any assertion to its evidence in two clicks | MUST |
| FR-10.6 | Redaction verification: documented data inventory the customer can hand their auditor | MUST |
| FR-10.7 | Agency-facing trust page with API access | SHOULD |

Rejected: full credential-custody SaaS. It would make us a processor of federal security data, likely forcing our own authorization early, and puts a breach-ends-the-business risk on a three-person company.

Our own FedRAMP Class A certification becomes both necessary and possible here, since we finally have a hosted service worth certifying.

## 20. Phase 4: Second backend, target 8 weeks

Target: CMMC and NIST 800-171.

RMF and eMASS is cheaper to build because it sits on 800-53 exactly as FedRAMP does, which is precisely why it is a poor experiment. CMMC is one honest step removed: same lineage, different scoping model, different assessment ecosystem. PCI DSS 4.0 is the strongest test and the largest market, but too far for backend two at this team size. It is backend three if CMMC goes well.

Exception: if a government anchor customer appears and wants RMF, build it for the revenue. Just log it separately and still run the CMMC experiment.

Requirements:

- Instrument the effort. Track engineering days on backend logic, IR extensions, and new front-end collection separately. The ratio is the finding.
- Zero front-end changes unless CMMC requires a genuinely new source of truth. Any front-end change is a leak; record it in an ADR.
- Written retrospective with actual numbers.

Decision gate:

| Result | Interpretation | Action |
|---|---|---|
| Under 8 weeks, minimal IR change | Thesis holds | Raise on it. PCI DSS and SOX ITGC next |
| 8 to 16 weeks, moderate IR change | Partially holds | Continue, re-forecast. Backends are a quarter each |
| Over 16 weeks, significant front-end change | Thesis is false | Stop expanding. Optimize as a focused FedRAMP business |

---

# Part V: Framework portfolio

## 21. Tier 1, build these

| Framework | Why it fits | Notes |
|---|---|---|
| FedRAMP 20x | Machine-readable spec, continuous validation mandated | Backend one |
| CMMC / NIST 800-171 | 800-53 lineage, prescriptive technical controls | Backend two. Also reaches non-DoD contractors via the FAR CUI rule |
| PCI DSS 4.0 | Extremely prescriptive, almost entirely technical | Best non-federal target. Least narrative content of anything here |
| SOX ITGC | Access provisioning, change management, segregation of duties, all derivable from IaC and CI logs | Enormous, audit-firm dominated, nobody attacking from the infrastructure side |
| SOC 2 Type II | Already in our flow as the Class A prerequisite | Caution: Vanta and Drata's core. Better as attach revenue than as a wedge |

## 22. Tier 2, later or narrower

RMF and eMASS, ISO 27001/27017/27018, HITRUST CSF, DORA, NIS2, GovRAMP and StateRAMP, DoD SRG IL2 through IL6, CJIS Security Policy, IRS Publication 1075, NERC CIP.

## 23. HIPAA: wait

The HHS OCR Security Rule NPRM published January 6, 2025; comments closed March 7, 2025 with over 4,000 received. `[verified]` It would remove the required-versus-addressable distinction and make encryption, MFA, asset inventory, annual penetration testing, and 72-hour incident reporting mandatory, which would turn HIPAA into something a compiler can target. `[verified]`

Not finalized. OCR's agenda listed May 2026 for final action, which passed with nothing published; the Unified Agenda now targets July 2027. `[reported]` Could be delayed further, weakened, or withdrawn.

Do not build on the proposed rule. Track it. Serve healthcare through HITRUST, which is prescriptive today and commercially better anyway. `[inference]`

## 24. Out of scope permanently

GDPR, CCPA, HIPAA Privacy Rule. These are legal interpretation, data mapping, and consent problems. The evidence does not live in infrastructure.

## 25. The selection rule

When asked whether to add framework X, the question is not market size. It is: what fraction of X's evidence is derivable from the IR we already build? Above roughly 70%, it is a backend. Below that, it is a new company.

Framework sprawl driven by individual customer requests is the most likely way this architecture rots.

---

# Part VI: Operating context

## 26. Open source strategy

| Open, Apache 2.0 | Closed |
|---|---|
| Rules ingestion library | Front-end collectors |
| JSON schema model | The IR |
| Ruleset differ | Backend artifact generation |
| Rego KSI evaluation modules | Agent layer |

Rationale: the rules are already public, so open sourcing the parsing layer costs nothing and makes us the reference implementation. It also supports the FedRAMP industry partnership conversation. Standard-setting, not altruism.

NTC-0009 states FedRAMP will not build this tooling and expects industry to, and names the OSCAL Foundation as an established partner with free general membership. `[verified]`

## 27. Documentation requirements

- Getting started under 30 minutes from install to first output
- Published coverage matrix: which rules we automate, assist, and do not touch. Publishing gaps builds more trust than hiding them, and assessors will find them anyway
- Assessor-facing methodology documentation explaining how to verify our output independently

## 28. Never build

A vulnerability scanner (ingest only). A generic GRC platform with policies, training, and vendor management. A DOCX or XLSX exporter. Anything for GDPR, CCPA, or HIPAA Privacy. Managed hosting of customer workloads.

## 29. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Crosswalk shows low overlap, substrate thesis fails | Critical | Phase 0 tests it before we build on it |
| IR leaks; every backend costs like a new product | Critical | Boundary enforcement in CI; ADRs on every leak; Phase 4 measures it |
| Hyperscaler ships free KSI evidence collection | High | Differentiator is the CI gate, multi-cloud, and the assessor artifact, not collection. Monitor AWS and Azure releases |
| Assessors reject our output format | High | Bring an assessor in during Phase 1. Acceptance is an exit criterion |
| Self-funded runway forces services work | High | Assume it. Budget slower phases rather than pretending otherwise |
| CR26 rules change materially | Medium | Ruleset differ built in Phase 0 makes this operational. Rules valid through 2028 |
| Incumbent ships a 20x product first | Medium | Likely. Compete on architecture and assessor preference, not on being first with a checkbox |
| Framework sprawl from customer requests | Medium | The 70% selection rule. Enforce in writing |
| Solo dependency on the IR author | Medium | Pair on IR design. Nobody can be the only person who understands it |

## 30. Legal gates, blocking

Two items must be cleared before writing the compiler, per `funding-and-ip-structure.md`:

1. Government contracts attorney on FAR 9.5 organizational conflict of interest exposure and mitigability
2. Written employer position on invention assignment scope

Phase 0 work (crosswalk, rules ingestion, repo foundations) creates little exposure and may proceed. The first real parser should wait.

Funding vehicle: SBIR, not conventional contract. Under SBIR, government gets limited and restricted rights for 20 years from award, then government purpose rights permanently, never unlimited. `[verified]` Under standard mixed-funding DFARS 252.227-7014, government gets government purpose rights for a nominal five years, then unlimited rights. `[verified]` That difference is the largest value swing available.

## 31. Open decisions

Resolved:

- Backend one is FedRAMP 20x, not RMF. Section 3.
- Backend two is CMMC and 800-171, chosen as a thesis test. Section 20.
- Deployment is CLI-first, hosted findings-only plane in year two. Section 19.

Still open:

1. Design partner. Ideal is a commercial SaaS company facing the 2027 deadlines. If the network produces a government partner instead, take it for revenue but find a commercial one too, or Phase 1 requirements drift toward one customer.
2. Services bridge. Recommend yes, capped at a fixed fraction of the week, scoped as FedRAMP package work so it doubles as research.
3. Class A subject. Recommend the eventual hosted control plane, with Phase 0 only starting the SOC 2 clock.
4. Company and product name, and domain. `substrate` is a working placeholder. Run a trademark search.
5. Entity and jurisdiction. Needed before the SOC 2 engagement.
6. Advisory services listing on the FedRAMP Marketplace, which CR26 opens in 2026. Recommend yes eventually, not before we have something to advise on.
7. Independent assessment service recognition. CR26 permits doing both with disclosure. `[verified]` Recommend no for two years; being the neutral tool every assessor likes is worth more.
8. AI model and vendor selection, and whether customers accept their infrastructure being read by a hosted model. Real objection in this market. Ask in discovery.
