package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// configConfigurationSettings is the control assignment for an AWS
// Config recorder's enablement state: base CM-6 (Configuration
// Settings), not an enhancement. Confirmed against the vendored
// FedRAMP dataset (internal/rules/data/fedramp-consolidated-rules.json)
// before proposing: cm-6 is cited by KSI-CMT-LMC, KSI-CMT-RMV,
// KSI-MLA-EVC, and KSI-SVC-ACM - the same dataset-first discipline
// every other collector's control choice in this package follows.
// CM-2 (Baseline Configuration) was the considered alternative (also
// cited by KSI-MLA-EVC and KSI-SVC-ACM, similar total citation count)
// but CM-6's "monitor and control changes to configuration settings"
// is the closer semantic fit for what a recorder's on/off status
// actually evidences; CM-2 is about defining and documenting a
// baseline, evidence this collector doesn't produce. Proposed and
// approved 2026-09-21 alongside this collector's first implementation.
var configConfigurationSettings = ir.Control{Family: "CM", Base: 6}

// ConfigToIR converts g's recorders into IR nodes, one per resolved
// recorder - including the synthetic Present:false entry
// CollectConfig produces when no recorder exists at all
// (ConfigRecorder's own doc comment on why that's a real fact, not
// silence). A recorder whose fact could not be resolved
// (Provenance.Confidence != Deterministic) produces no node, the same
// "never guess" treatment every other mapper in this codebase applies.
func ConfigToIR(g *ConfigGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, r := range g.Recorders {
		if node, ok := mapConfigRecorder(r); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapConfigRecorder records r's enablement state verbatim (FR-5.9's
// measurement-not-verdict split: this mapper records whether a recorder
// exists and is recording, never whether its recorded scope is
// sufficient - that's the RecordingGroup detail this collector defers,
// and ultimately a backend predicate's job regardless).
func mapConfigRecorder(r ConfigRecorder) (ir.Node, bool) {
	if r.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	resource := r.Name
	if resource == "" {
		resource = "none"
	}

	return ir.Node{
		ID:            awsNodeID("config", resource, "enablement"),
		ControlFamily: configConfigurationSettings.Family,
		Controls:      []ir.Control{configConfigurationSettings},
		Kind:          "aws_config_recorder",
		Attributes: map[string]string{
			"present":     strconv.FormatBool(r.Present),
			"recording":   strconv.FormatBool(r.Recording),
			"last_status": r.LastStatus,
		},
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
