# Crosswalk Analysis

## Does the substrate thesis hold at the artifact level?

Ticket: T-001
Date: September 10, 2026
Gate: `docs/REQUIREMENTS.md` section 16.1
Analyst: prepared for founder review. Every score is a judgment call and every one is auditable. Change any row and recompute.

---

## 1. Headline

**Overall artifact-level overlap: 69.6%. Infrastructure-derivable subset: 82.0%.**

The gate in section 16.1 says below 60% stop, 60 to 70% proceed with explicit extension points, above 70% proceed with confidence.

The overall number lands at 69.6%, inside the caution band by four tenths of a point. That is uncomfortably close to a coin flip and I do not want to paper over it.

But the overall number is measuring the wrong thing, and the reason is the most important finding in this analysis. Nine of the 46 objectives are not infrastructure requirements at all. Background checks, training completion, disaster recovery exercises, incident response tabletops, and cryptographic key ceremonies with split knowledge are human and procedural artifacts. No compiler reads them out of Terraform, and no competitor's compiler will either. Including them in the denominator measures how much of compliance is infrastructure, not whether infrastructure evidence is reusable across frameworks.

Restricted to the 37 objectives that are actually infrastructure-derivable, overlap is 82.0%, comfortably above the confidence threshold.

**Recommendation: GO, with two conditions.** Stated in section 8.

---

## 2. Method

### 2.1 What was compared

| Framework | Version | Sourcing confidence |
|---|---|---|
| FedRAMP 20x Key Security Indicators | CR26, dataset 2026.07.14.01 | High. Primary source, machine-readable, with FedRAMP's own 800-53 mappings published per KSI |
| NIST SP 800-171 | Rev 3 | High. Public domain, and 800-171A r3 supplies assessment objectives |
| PCI DSS | 4.0.1 | **Low to moderate.** Text is copyrighted and not available to this analysis. Scored from requirement numbers and public summaries. See section 9 |
| CJIS Security Policy | 6.1, June 25, 2026 | Moderate to high. Freely published |

CJIS was added as a control case. That turned out to matter: CJIS v6.0 restructured the policy onto NIST 800-53 control families, and v6.1 continues that, so 18 of its 20 policy areas *are* 800-53 families. It therefore flatters the thesis almost by construction, and its 86.5% derivable-subset score should be read as a ceiling rather than as independent confirmation.

46 objectives, spanning 12 NIST 800-53 control families (AC, IA, AU, CM, SC, SI, RA, CP, SR, IR, AT, PS). The ticket asked for 40 objectives across at least 4 families.

### 2.2 A finding that changed the work

FedRAMP publishes the KSI-to-800-53 mapping itself. Every KSI in CR26 carries a "Related SP 800-53 Controls" list, and `KSI-MLA-OSM` alone maps to 17 controls across AU, AC, IR and SI. NIST publishes an 800-171-to-800-53 mapping. CJIS 6.1 is organized by 800-53 family.

This means the control-level crosswalk is largely a lookup, not an analysis. Three of the four frameworks anchor on 800-53 natively. That is strong external validation of the decision to key the IR on 800-53 control families, and it means the only genuinely hard question is the artifact-level one, which is what this document scores.

It also means a competitor can obtain the control-level mapping as cheaply as we can. The mapping is not a moat. The evidence collection and the artifact-level reconciliation are.

### 2.3 Scoring rubric

For each objective, I defined the underlying fact a compiler would collect, then asked of each framework pair: **would the same collected fact, at the granularity we would collect it, satisfy both frameworks' evidence expectation?**

| Score | Meaning |
|---|---|
| 2 | Full. Same fact, same granularity. One collection satisfies both. Backend difference is serialization only |
| 1 | Partial. Same fact, but the frameworks assert different predicates over it, or one demands additional enrichment, cadence, or attestation. Backend needs framework-specific logic but no new collection |
| 0 | None. The frameworks want materially different artifacts. New collection, human attestation, or third-party record required |

Each objective scored three times, against FedRAMP 20x as the anchor since it is backend one. Maximum 6 per objective, 276 total.

The distinction between 2 and 1 is where the thesis lives. A score of 1 still means the front end is shared and only the backend differs, which is the architecture working as designed. A score of 0 is a genuine leak.

### 2.4 What "artifact level" excludes

Deliberately not counted as overlap: both frameworks mentioning encryption, both mapping to the same 800-53 control, both having a requirement with a similar title. The test is whether one collected fact discharges both evidence obligations.

---

## 3. Results

```
OVERALL                     192/276  =  69.6%
  infrastructure-derivable  182/222  =  82.0%   (37 objectives, 80% of set)
  non-derivable              10/54   =  18.5%   ( 9 objectives)

PER PAIR (all objectives)            (derivable only)
  FedRAMP 20x <-> 800-171 r3   75.0%      86.5%
  FedRAMP 20x <-> PCI DSS      62.0%      73.0%
  FedRAMP 20x <-> CJIS 6.1     71.7%      86.5%

JUDGMENT DISTRIBUTION
  score 2 (full)     72   52.2%
  score 1 (partial)  48   34.8%
  score 0 (none)     18   13.0%
```

The single most encouraging number: **PCI DSS, the most architecturally distant framework, scored conservatively under low-confidence sourcing, still reaches 73.0% on the derivable subset.** If the thesis survives PCI it survives most things.

The single most concerning number is in the sensitivity analysis below.

### 3.1 Sensitivity

Because PCI sourcing is weak, I recomputed with every PCI judgment downgraded one step.

| Scenario | Overall | Derivable only |
|---|---|---|
| As scored | 69.6% | 82.0% |
| Every PCI judgment downgraded one step | 55.4% | 65.8% |
| Excluding CJIS (harder test, 800-171 and PCI only) | 68.5% | 79.7% |

The downgrade scenario drops the overall figure below the stop threshold and the derivable figure into the caution band. PCI is the swing factor. This is the reason condition 2 in section 8 exists.

Removing CJIS barely moves the result, which is reassuring: the finding is not an artifact of having included a framework that is 800-53 in a different wrapper.

---

## 4. The table

Derivable = can the underlying fact be obtained from IaC, cluster manifests, CI config, identity provider, or cloud control plane. Scores are FedRAMP 20x versus each framework.

| # | Objective | 800-53 | Anchor KSI | Deriv | 171 | PCI | CJIS | Σ |
|---|---|---|---|---|---|---|---|---|
| 1 | Account lifecycle automation | AC-02 | KSI-IAM-AAM | Y | 2 | 1 | 2 | 5 |
| 2 | Privileged account inventory and separation of duties | AC-05, AC-06 | KSI-IAM-JIT | Y | 2 | 2 | 2 | 6 |
| 3 | Least privilege on roles and policies | AC-06 | KSI-IAM-ELP | Y | 2 | 2 | 2 | 6 |
| 4 | Just-in-time / time-bound elevation | AC-02(01) | KSI-IAM-JIT | Y | 1 | 1 | 1 | 3 |
| 5 | Session timeout and termination | AC-11, AC-12 | KSI-IAM-ELP | Y | 2 | 2 | 2 | 6 |
| 6 | Remote access control and encryption | AC-17 | KSI-IAM-ELP | Y | 2 | 2 | 2 | 6 |
| 7 | Disable accounts on suspicious activity | AC-02(13) | KSI-IAM-SUS | Y | 1 | 1 | 1 | 3 |
| 8 | External system and service connections | AC-20 | KSI-IAM-ELP | Y | 1 | 1 | 1 | 3 |
| 9 | Periodic access review and recertification | AC-06(07) | KSI-IAM-ELP | Y | 1 | 1 | 1 | 3 |
| 10 | Wireless access restriction and rogue AP detection | AC-18 | KSI-CNA-MAT | **N** | 1 | 0 | 1 | 2 |
| 11 | Phishing-resistant MFA for user accounts | IA-02(01), IA-02(02) | KSI-IAM-APM | Y | 2 | 1 | 2 | 5 |
| 12 | Non-user and service account authentication | IA-03, IA-05(02) | KSI-IAM-SNU | Y | 1 | 2 | 1 | 4 |
| 13 | Credential and secret rotation | IA-05, SC-12 | KSI-SVC-ASM | Y | 2 | 2 | 2 | 6 |
| 14 | Password / authenticator strength policy | IA-05(01) | KSI-IAM-APM | Y | 2 | 2 | 2 | 6 |
| 15 | Identity proofing and enrollment | IA-12 | KSI-IAM-AAM | **N** | 1 | 0 | 0 | 1 |
| 16 | Log event type definition and coverage | AU-02, AU-12 | KSI-MLA-LET | Y | 2 | 2 | 2 | 6 |
| 17 | Centralized tamper-resistant log storage | AU-09 | KSI-MLA-OSM | Y | 2 | 2 | 2 | 6 |
| 18 | Log retention period | AU-11 | KSI-MLA-OSM | Y | 2 | 1 | 2 | 5 |
| 19 | Log review cadence and evidence of review | AU-06 | KSI-MLA-RVL | Y | 1 | 1 | 1 | 3 |
| 20 | Time synchronization for log correlation | AU-08 | KSI-MLA-OSM | Y | 2 | 2 | 2 | 6 |
| 21 | Log access restriction | AU-09(04), SI-11 | KSI-MLA-ALA | Y | 2 | 2 | 2 | 6 |
| 22 | Baseline configuration defined | CM-02 | KSI-SVC-ACM | Y | 2 | 2 | 2 | 6 |
| 23 | Configuration drift detection | CM-06, CA-07 | KSI-SVC-ACM | Y | 1 | 1 | 1 | 3 |
| 24 | Change approval workflow | CM-03, CM-05 | KSI-CMT (change mgmt) | Y | 2 | 1 | 2 | 5 |
| 25 | Least functionality, unnecessary services disabled | CM-07 | KSI-CNA-DFP | Y | 2 | 2 | 2 | 6 |
| 26 | Asset inventory completeness | CM-08 | KSI-PIY (policy/inventory) | Y | 2 | 2 | 2 | 6 |
| 27 | Software and resource integrity verification | SI-07, CM-08(03) | KSI-SVC-VRI | Y | 2 | 1 | 2 | 5 |
| 28 | Encryption in transit | SC-08, SC-08(01) | KSI-SVC-SIN | Y | 2 | 2 | 2 | 6 |
| 29 | Encryption at rest | SC-28, SC-28(01) | KSI-SVC-SIN | Y | 2 | 1 | 2 | 5 |
| 30 | Cryptographic key management and rotation | SC-12, SC-17 | KSI-SVC-ASM | Y | 2 | 1 | 2 | 5 |
| 31 | Key ceremony split knowledge and dual control | SC-12 | none | **N** | 0 | 0 | 0 | 0 |
| 32 | Network segmentation and traffic flow enforcement | SC-07(07), AC-04 | KSI-CNA-ULN | Y | 2 | 1 | 2 | 5 |
| 33 | Boundary protection, ingress and egress restriction | SC-07, SC-07(05) | KSI-CNA-RNT | Y | 2 | 2 | 2 | 6 |
| 34 | Denial of service protection effectiveness | SC-05, SI-08 | KSI-CNA-RVP | Y | 1 | 0 | 1 | 2 |
| 35 | Segmentation validated by penetration test | CA-08 | none | **N** | 0 | 0 | 0 | 0 |
| 36 | Vulnerability scanning and remediation | RA-05 | KSI-SVC-EIS | Y | 2 | 1 | 2 | 5 |
| 37 | Malware protection | SI-03 | KSI-IAM-ELP | Y | 2 | 2 | 2 | 6 |
| 38 | File and resource integrity monitoring | SI-07(01) | KSI-SVC-VRI | Y | 1 | 2 | 1 | 4 |
| 39 | Flaw remediation timelines | SI-02 | KSI-SVC-EIS | Y | 2 | 1 | 2 | 5 |
| 40 | Backup configuration and encryption | CP-09, CP-09(08) | KSI-RPL (recovery) | Y | 2 | 1 | 2 | 5 |
| 41 | Recovery and disaster recovery exercise | CP-04 | KSI-RPL | **N** | 0 | 0 | 0 | 0 |
| 42 | SBOM and component provenance | SR-10, SR-11 | KSI-SVC-VRI | Y | 1 | 1 | 1 | 3 |
| 43 | Incident response plan testing | IR-03 | KSI-INR | **N** | 0 | 0 | 0 | 0 |
| 44 | Security awareness training completion | AT-02 | KSI-CED-RAT | **N** | 1 | 1 | 1 | 3 |
| 45 | Role-based secure development training | AT-03 | KSI-CED-RAT | **N** | 1 | 1 | 0 | 2 |
| 46 | Personnel screening and background checks | PS-03 | KSI-IAM-ELP (via PS-03 map) | **N** | 1 | 1 | 0 | 2 |

Row 46 deserves a note. FedRAMP maps PS-02 through PS-06 into `KSI-IAM-ELP` and `KSI-IAM-JIT`, meaning personnel screening is formally reachable through an identity-and-access KSI. That is a mapping artifact, not a claim that background checks are derivable from IAM configuration. It is a good illustration of why control-level mapping is not the same as artifact-level overlap, and why this analysis was worth doing rather than just consuming FedRAMP's published crosswalk.

---

## 5. Cadence and acceptor

The ticket asked for assessment frequency and who accepts the evidence. These are almost entirely framework-level properties rather than per-objective, so recording them once is more useful than repeating them 46 times.

| Framework | Cadence | Who accepts | Evidence form |
|---|---|---|---|
| FedRAMP 20x | Continuous validation, plus annual independent verification and validation. Class A assessment optional, B/C/D mandatory | FedRAMP-recognized independent assessment service; agencies consume ongoing data | Machine-readable primary, human-readable generated from it. Five artifacts per rule and per KSI: explanation, verification, validation, independent verification, independent validation |
| NIST 800-171 r3 | Triennial under CMMC, with annual affirmation. Self-assessment or C3PAO depending on level | C3PAO or self-affirmed; DoD contracting officer | 800-171A determination statements: examine, interview, test |
| PCI DSS 4.0.1 | Annual assessment, quarterly external scans by an approved scanning vendor, and various sub-annual requirements | Qualified Security Assessor for the Report on Compliance; acquirer or brand | Testing procedures per requirement; observation and examination evidence; some requirements demand a named accountable party |
| CJIS 6.1 | Triennial audit | FBI CJIS Audit Unit and CJIS Systems Agency | Policy-area evidence, largely 800-53 aligned since v6.0 |

Two implications for the product.

Cadence mismatch is a scheduling problem, not an architecture problem. Collect continuously, project onto whatever assessment window a framework wants. This is a point in favor of the design, since the highest-frequency requirement (FedRAMP continuous) dominates and everything else is a subset.

Acceptor mismatch is not solvable by us. A QSA has to sign a Report on Compliance and an ASV has to run the external scan. We can make their work cheaper and better-evidenced. We cannot replace them, and the product should never imply otherwise.

---

## 6. Three genuine overlaps

### 6.1 Log access restriction (row 21, score 6/6)

The fact: which principals hold read permission on log storage, derived from IAM policy documents, bucket policies, and log group access configuration, plus the observed set of principals who actually accessed logs from control plane audit records.

`KSI-MLA-ALA` requires a least-privileged, role and attribute-based, just-in-time model, persistently reviewed. 800-171 r3 and CJIS both want audit information protected from unauthorized access. PCI DSS requirement 10.3 covers log file protection and access limitation.

One collection satisfies all four. The predicates differ slightly in strictness, but there is no framework here asking for a different kind of evidence. The backends differ only in how the same fact is serialized and which threshold is asserted.

This is the archetype the whole product is built for.

### 6.2 Encryption in transit (row 28, score 6/6)

The fact: TLS configuration per listener and per service, including minimum protocol version and cipher suites, from load balancer and ingress definitions in IaC, plus observed negotiated versions from runtime probes.

All four frameworks require strong cryptography for data in transit over untrusted networks. The version floors differ across frameworks and change over time, but the collected fact is identical and the difference lives entirely in a comparison against a version threshold.

Note that the declared-versus-observed split matters here and maps exactly onto CR26's IVV-CSO-SEI and IVV-CSO-SEE distinction. The IaC says TLS 1.2 minimum; the runtime probe proves that TLS 1.0 is actually refused. Both are needed, both are collected once, and both feed every backend.

### 6.3 Baseline configuration and least functionality (rows 22 and 25, score 6/6 each)

The fact: the declared resource configuration graph from Terraform and Kubernetes, including enabled services, open ports, installed packages, and container capabilities, diffed against a defined baseline.

CM-02 and CM-07 are among the most consistently expressed requirements across all four frameworks. PCI's requirement 2 on secure configurations, CJIS's configuration management policy area, and 800-171's configuration management family all want the same underlying artifact: proof that a baseline exists and that running state matches it.

This one is worth noting because it is where the CI gate delivers something none of the frameworks anticipated. They all assume a periodic comparison. We can assert it on every pull request.

---

## 7. Three false friends

These look like overlaps at the control level and are not overlaps at the artifact level. They are the evidence that the artifact-level test was the right test.

### 7.1 Cryptographic key management (row 30, score 5/6) versus key ceremonies (row 31, score 0/6)

Both frameworks list SC-12. Both talk about key management. At control level this looks like a clean match.

`KSI-SVC-ASM` asks that management, protection, and rotation of keys, certificates, and secrets be automated and persistently reviewed. That is directly derivable: KMS key policies, rotation status, certificate expiry, secret manager configuration.

PCI DSS requirements 3.6 and 3.7 additionally require, for manual clear-text key operations, split knowledge and dual control. That is a ceremony performed by two named humans with a signed record. It is not in Terraform. It cannot be inferred from any cloud API. It is a scanned form in a binder.

The lesson: a single 800-53 control can contain both a fully derivable element and a fully non-derivable one. The IR must be able to represent partial satisfaction of a control, with the derivable portion evidenced and the remainder explicitly marked as requiring human attestation. If the model forces a control to be satisfied or not satisfied, this row breaks it.

### 7.2 Network segmentation (row 32, score 5/6) versus segmentation validation (row 35, score 0/6)

`KSI-CNA-ULN` and `KSI-CNA-RNT` want logical networking and traffic flow controls, persistently reviewed. Fully derivable: security groups, network ACLs, Kubernetes NetworkPolicies, service mesh authorization policies, route tables.

PCI DSS requirement 11.4.5 requires service providers to validate segmentation controls by penetration testing at a defined frequency. The artifact is a penetration test report produced by a qualified tester. We can supply the tester with a precise, current topology, which is genuinely valuable and shortens their engagement. We cannot produce the report.

The lesson: several frameworks require *independent human validation of a thing we can prove mechanically*. The product's role there is to feed the human, not to replace them. That is a real business, but it is a different value proposition and it should be priced and described differently.

### 7.3 Security awareness training (row 44, score 3/6, non-derivable)

`KSI-CED-RAT` asks that the *effectiveness* of training be persistently reviewed, and specifically names general training, role-specific training for high-risk roles, secure software delivery training for engineers, and training for incident response and disaster recovery staff.

800-171, PCI requirement 12.6, and CJIS all require security awareness training too, so at control level AT-02 looks like a four-way match. It scores 3 rather than 0 because the underlying record (who completed what, when) is genuinely the same fact across frameworks.

But it is not an infrastructure fact. It lives in a learning management system, and reaching it means building an LMS connector, which is a new front-end source with its own auth model and its own vendor fragmentation. Worse, FedRAMP asks about *effectiveness*, not completion, which is a qualitative judgment that no connector produces.

The lesson: shared facts do not imply cheap facts. This row would be a real overlap if we built the collector, and it is the clearest example of a place where the honest answer is that the product covers the requirement partially and says so in the coverage report.

---

## 8. Recommendation

**GO**, conditional on two things.

The derivable-subset result of 82.0% clears the confidence threshold, and it clears it on the measurement that actually predicts the cost of backend two. The most distant framework, scored conservatively, still reaches 73.0%. The result barely moves when the flattering framework is removed. Three of four frameworks anchor natively on 800-53, which independently validates the IR keying decision.

### Condition 1: scope the product explicitly to the derivable subset, and publish that scope

The 82% figure is only honest if we are explicit that roughly 20% of what these frameworks require is not infrastructure evidence and never will be. That is not a gap to close later, it is a permanent boundary of the product.

This is already in `docs/REQUIREMENTS.md` as FR-6.7, the coverage report. This analysis says that requirement is not a nice-to-have, it is the thing that keeps our claims truthful. Publishing which requirements we automate, which we assist, and which we do not touch should happen from the first release.

The good news is that 80% of objectives being derivable is a strong product, and the 20% is where a services attach or a partner integration can live.

### Condition 2: re-validate the PCI leg before it informs a funding conversation

PCI is the swing factor. Downgrading every PCI judgment one step takes the overall figure to 55.4% and the derivable figure to 65.8%, which would move the recommendation from GO to caution.

My PCI sourcing is genuinely weak. I could not work from the standard text. Before this number appears in an investor deck, a board memo, or a strategy document, someone with access to PCI DSS 4.0.1 and preferably QSA experience should re-score the 12 PCI columns. That is a day of work and it is the difference between a defensible number and a plausible one.

Until then, quote the pairwise 800-171 figure (86.5% derivable, high sourcing confidence) rather than the blended one when precision matters.

---

## 9. Design consequences for the build

Four things this analysis says the IR must support. These belong in T-010 before the types are frozen.

**Partial control satisfaction.** Row 31 proves a single control can be half derivable and half ceremonial. The IR cannot model control satisfaction as a boolean or a four-state enum alone. It needs to represent which portion of a control is evidenced mechanically and which requires attestation, with both visible in the coverage report.

**Predicates belong in backends, facts belong in the IR.** Row 18 is the clean case. Log retention is one collected fact, an integer of days, and each framework asserts a different minimum against it. If the IR ever stores "meets retention requirement" rather than "retention is N days", the abstraction has leaked. Store the measurement, assert in the backend.

**Declared and observed are both required and both reusable.** Row 28 shows the split working exactly as CR26's IVV-CSO-SEI and SEE describe, and the same split serves all four frameworks. This confirms the first-class field in FR-4.2 rather than treating it as FedRAMP-specific.

**A third evidence class is needed: human-attested.** Rows 31, 35, 41, 43 and 46 are not `undetermined`. They are determinately outside the compiler's reach. Collapsing them into `undetermined` would misrepresent the product's coverage and would be caught by an assessor. Add an explicit `requires_attestation` state with a recorded attester and date, distinct from `undetermined`.

---

## 10. Limitations

Stated plainly so nobody over-reads this document.

PCI DSS scoring is inference-level throughout. Copyrighted text was not available. Requirement numbers referenced are from public summaries and my own knowledge, and both could be wrong in specifics.

Scores are one analyst's judgment. The 2-versus-1 boundary in particular is soft. The distribution (52% full, 35% partial, 13% none) is stable enough that individual row disagreements will not move the headline much, but a systematic bias would.

46 objectives is a sample, not a census. FedRAMP alone has 46 KSIs and 246 FRR rules; PCI has hundreds of sub-requirements. This sample was chosen to span families and to deliberately include hard cases, which if anything biases the result downward.

CJIS 6.1 is 800-53 restructured, so its high score is partly definitional. It was included as a control case and should be read that way.

NIST 800-171 r3 scoring did not use the 800-171A r3 assessment procedures directly. Doing so would tighten the artifact-level judgments and is the cheapest available improvement to this analysis.

Nothing here has been reviewed by an assessor. Three FedRAMP-recognized assessors are in the T-013 discovery list, and asking them to challenge the 2-versus-1 calls on ten rows would be a high-value hour.

---

## 11. Sources

- [FedRAMP CR26, Key Security Indicators](https://www.fedramp.gov/2026/providers/20x/key-security-indicators/)
- [KSI: Identity and Access Management](https://www.fedramp.gov/2026/providers/20x/key-security-indicators/identity-and-access-management/)
- [KSI: Monitoring, Logging, and Auditing](https://www.fedramp.gov/2026/providers/20x/key-security-indicators/monitoring-logging-and-auditing/)
- [KSI: Service Configuration](https://www.fedramp.gov/2026/providers/20x/key-security-indicators/service-configuration/)
- [KSI: Cloud Native Architecture](https://www.fedramp.gov/2026/providers/20x/key-security-indicators/cloud-native-architecture/)
- [KSI: Cybersecurity Education](https://www.fedramp.gov/2026/providers/20x/key-security-indicators/cybersecurity-education/)
- [FedRAMP CR26, Independent Verification and Validation](https://www.fedramp.gov/2026/providers/20x/rules/independent-verification-and-validation/)
- [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final)
- [NIST SP 800-171A Rev. 3, assessment procedures](https://csrc.nist.gov/pubs/sp/800/171/a/r3/final)
- [CJIS Security Policy 6.0 restructure onto 800-53 families](https://www.diversecti.com/2026/01/09/cjis-security-policy-6-0/)
- [CJIS Security Policy overview and policy areas](https://www.saltycloud.com/blog/cjis-security-policy/)
- PCI DSS 4.0.1: requirement numbers referenced from public summaries. Standard text not consulted. See section 10.

Scoring script that produced the figures in section 3 is reproduced in appendix A so the arithmetic is auditable.

---

## Appendix A: scoring script

The 46 rows and their scores, with the computation. Re-run after changing any row.

```python
# rows: (id, label, family, derivable, f_171, f_pci, f_cjis)
# See section 4 for the table. Overall = sum(scores) / (len(rows)*6)
# Derivable-only = same, restricted to derivable == 1
# Reported: 192/276 = 69.6% overall; 182/222 = 82.0% derivable-only
```

Full script is committed alongside this document as `crosswalk-score.py` so the numbers regenerate rather than being retyped.
