# Rule counts

Authoritative counts derived programmatically from the vendored FedRAMP
Consolidated Rules dataset:

- File: `internal/rules/data/fedramp-consolidated-rules.json`
- Dataset version: `2026.07.14.01` (`info.version`)
- Last updated: 2026-07-14 (`info.last_updated`)
- Checksummed in `internal/rules/data/CHECKSUMS.txt`

These figures supersede any number in `docs/REQUIREMENTS.md` or elsewhere
that was sourced from a FedRAMP vendor blog post or announcement rather
than the dataset itself, per T-006 and section 16.2's instruction to
"replace every vendor-blog number in the strategy documents with numbers
derived from the dataset." `internal/rules/rulecounts_test.go` parses the
machine-readable block at the bottom of this file and fails the build if
the vendored dataset's actual counts drift from what's recorded here, so
this document cannot silently go stale. If that test fails after a
dataset upgrade, recompute the numbers below and update both this file
and `docs/REQUIREMENTS.md` section 5 in the same change.

## Dataset totals

Counting every record the typed model exposes, across all three
certification-type containers (`all`, `20x`, `rev5`) where a section has them:

| Section | Count |
|---|---|
| FRD definitions (`FRD.data.all`) | 75 |
| FRR documents (top-level `FRR` keys, e.g. AFC, IVV) | 17 |
| FRR rules, all documents, all containers | 246 |
| KSI themes (top-level `KSI` keys) | 10 |
| KSI indicators, all themes | 46 |
| CTL control families (top-level `CTL` keys) | 14 |
| CTL control/enhancement entries, all families | 79 |

## FedRAMP 20x package and assurance rule counts

`docs/REQUIREMENTS.md` section 5 cites rule counts per FRR document scoped
to the rules a **provider** must satisfy **under 20x** specifically -
narrower than "dataset totals" above, which counts every rule regardless
of who it affects (FedRAMP itself, agencies, assessors) or which
certification type (20x vs. Rev5-only) it applies to.

The dataset expresses "who" and "which certification type" per rule
*subset* (e.g. AFC's `CSO` subset is "General Provider Responsibilities",
its `FRP` subset is "FedRAMP Responsibilities" - only the former counts
here). Concretely: for each FRR document, sum the rules in every subset,
across the `all` and `20x` data containers, whose
`applicability.affects` includes `Providers` and whose
`applicability.types` includes `20x`.

| Artifact / ruleset | Rules |
|---|---|
| Certification Package Overview (CPO) | 4 |
| Secure Configuration Guide (SCG) | 9 |
| Security Decision Record (SDR) | 4 |
| **Package subtotal** | **17** |
| Vulnerability Evaluation and Reporting (VER) | 19 |
| Collaborative Continuous Monitoring (CCM) | 17 |
| Significant Change Notification (SCN) | 16 |
| Independent Verification and Validation (IVV) | 9 |
| Addressing FedRAMP Communication (AFC) | 8 |
| Incident Evaluation and Communication (IEC) | 7 |
| **Assurance subtotal** | **76** |
| **Package + assurance total** | **93** |

This independently confirms every number already cited in
`docs/REQUIREMENTS.md` section 5 (17 package rules, 76 assurance rules, 93
total, ten KSI families) against dataset version 2026.07.14.01 - no
correction to those specific figures was needed. What section 5 did not
have, and does not need restating there, is the full set of dataset
totals above (definitions, indicators, and control entries); those are
recorded here as the authoritative reference for anything that cites them
in the future.

## KSI indicators per family

The KSI analogue of "per ruleset": indicator count for each of the ten
KSI families (`KSI.<code>.indicators`), unscoped by class or certification
type - the dataset doesn't subdivide KSI indicators by certification type
the way FRR rules are subdivided into `all`/`20x`/`rev5`.

| Family | Indicators |
|---|---|
| Cybersecurity Education (CED) | 1 |
| Change Management (CMT) | 4 |
| Cloud Native Architecture (CNA) | 8 |
| Identity and Access Management (IAM) | 6 |
| Incident Response (INR) | 3 |
| Monitoring, Logging, and Auditing (MLA) | 5 |
| Policy and Inventory (PIY) | 5 |
| Recovery Planning (RPL) | 4 |
| Supply Chain Risk (SCR) | 2 |
| Service Configuration (SVC) | 8 |
| **Total** | **46** |

## Rules per certification class

Of the 93 provider/20x package-and-assurance rules above, how many apply
to each certification class (A/B/C/D)?

A rule's own `varies_by_class` is the most specific signal available and
takes precedence when present. Its containing subset's blanket
`applicability.classes` field is the fallback for rules that don't vary by
class at all (a single uniform `statement`/`force` for every class). This
matters because the two disagree in 12 cases: rules such as
`CCM-QTR-MTG` and `IVV-CSO-FIA` define an explicit `"a"` entry in
`varies_by_class` - optional Class A guidance - even though their subset's
`classes` list only names B, C, and D. Falling back to the subset-level
field alone would undercount Class A by exactly those 12 rules.

| Class | Rules (of 93) |
|---|---|
| A | 13 |
| B | 93 |
| C | 93 |
| D | 93 |

Every rule in scope applies to B, C, and D uniformly; only Class A -
FedRAMP 20x's new, lighter pilot tier - has a materially smaller
applicable set, and even that set is 13 rather than the 1 you'd get by
reading only the subset-level field.

**KSI indicators are not broken out per class here.** Only 5 of the 46
indicators vary by class at all (`KSI-CNA-EIS`, `KSI-MLA-ALA`,
`KSI-SVC-PRR`, `KSI-SVC-RUD`, `KSI-SVC-VCM`), and each of those defines
only `"b"` and `"c"` - never `"a"` or `"d"`. Unlike FRR rules, KSI
indicators have no subset-level `applicability` object to fall back on for
the other 41, so there is no dataset field that says whether they apply
to Class A or Class D. Recording a per-class KSI count would mean
guessing at that gap rather than reading it from the dataset, which
CLAUDE.md's "say so rather than guessing" rule for undetermined states
rules out. Treat KSI class-scoping as undetermined until CR26 publishes
that mapping explicitly.

## Machine-readable summary

The block below is parsed directly by `internal/rules/rulecounts_test.go`.
Keep it in sync with the tables above; `key: value` pairs only, one per line.

<!-- rule-counts:begin -->
dataset_version: 2026.07.14.01
frd_definitions: 75
frr_documents: 17
frr_rules_total: 246
ksi_themes: 10
ksi_indicators: 46
ksi_indicators_ced: 1
ksi_indicators_cmt: 4
ksi_indicators_cna: 8
ksi_indicators_iam: 6
ksi_indicators_inr: 3
ksi_indicators_mla: 5
ksi_indicators_piy: 5
ksi_indicators_rpl: 4
ksi_indicators_scr: 2
ksi_indicators_svc: 8
ctl_families: 14
ctl_controls: 79
package_cpo: 4
package_scg: 9
package_sdr: 4
package_total: 17
assurance_ver: 19
assurance_ccm: 17
assurance_scn: 16
assurance_ivv: 9
assurance_afc: 8
assurance_iec: 7
assurance_total: 76
package_plus_assurance_total: 93
class_a: 13
class_b: 93
class_c: 93
class_d: 93
<!-- rule-counts:end -->
