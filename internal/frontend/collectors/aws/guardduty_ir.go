package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// guardDutySystemMonitoring is the control assignment for a GuardDuty
// detector's enablement state: base SI-4 (System Monitoring), not an
// enhancement. Confirmed against the vendored FedRAMP dataset
// (internal/rules/data/fedramp-consolidated-rules.json) before
// proposing: si-4 (base) is cited by KSI-MLA-RVL and KSI-SVC-EIS, and
// SI-4 as a family (base plus enhancements si-4.2/.4/.5) has more total
// citations than any other candidate control checked for FR-3.6 -
// SI-4(5) "System-Generated Alerts" is almost GuardDuty's literal job
// description, but this collector only resolves whether a detector
// exists and is on, not that it's actually generating alerts (that's
// FR-3.6's separate, deferred findings half) - base is the honest claim
// this fact supports, the same "don't claim an enhancement your
// collected fact doesn't establish" reasoning aws.subnetBoundaryProtection
// and okta.mfaEnrollmentIA2 already apply. Proposed and approved
// 2026-09-21 alongside this collector's first implementation.
var guardDutySystemMonitoring = ir.Control{Family: "SI", Base: 4}

// GuardDutyToIR converts g's detectors into IR nodes, one per resolved
// detector - including the synthetic Present:false entry
// CollectGuardDuty produces when no detector exists at all (Detector's
// own doc comment on why that's a real fact, not silence). A detector
// whose fact could not be resolved (Provenance.Confidence !=
// Deterministic - a GetDetector API failure) produces no node, the same
// "never guess" treatment every other mapper in this codebase applies.
func GuardDutyToIR(g *GuardDutyGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, d := range g.Detectors {
		if node, ok := mapDetector(d); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapDetector records d's enablement state verbatim (FR-5.9's
// measurement-not-verdict split: this mapper records whether a detector
// exists and is on, never whether that's sufficient threat-detection
// coverage for the account - a backend predicate's job, if one is ever
// written for SI-4).
func mapDetector(d Detector) (ir.Node, bool) {
	if d.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	resource := d.DetectorID
	if resource == "" {
		resource = "none"
	}

	return ir.Node{
		ID:            awsNodeID("guardduty", resource, "enablement"),
		ControlFamily: guardDutySystemMonitoring.Family,
		Controls:      []ir.Control{guardDutySystemMonitoring},
		Kind:          "aws_guardduty_detector",
		Attributes: map[string]string{
			"present":                      strconv.FormatBool(d.Present),
			"enabled":                      strconv.FormatBool(d.Enabled),
			"finding_publishing_frequency": d.FindingPublishingFrequency,
		},
		Provenance:    d.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
