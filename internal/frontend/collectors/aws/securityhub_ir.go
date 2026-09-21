package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// securityHubContinuousMonitoring is the control assignment for Security
// Hub's subscription state: base CA-7 (Continuous Monitoring), not an
// enhancement. Confirmed against the vendored FedRAMP dataset
// (internal/rules/data/fedramp-consolidated-rules.json) before
// proposing: ca-7 is cited by KSI-MLA-EVC ("configuration... persistently
// evaluated and tested"), the same indicator AWS Config's CM-6 mapping
// already feeds - Security Hub's whole purpose (aggregated, continuous
// security posture monitoring) is CA-7's most literal match of any
// FR-3.6 service checked. Base, not an enhancement: this collector only
// resolves subscription state, not the actual continuous-monitoring
// activity (findings, standards compliance) CA-7's enhancements would
// need - FR-3.6's separate, deferred findings half. Proposed and
// approved 2026-09-21 alongside this collector's first implementation.
var securityHubContinuousMonitoring = ir.Control{Family: "CA", Base: 7}

// SecurityHubToIR converts g's hub state into an IR node - including
// the synthetic Present:false entry CollectSecurityHub produces when
// the account is confirmed not subscribed (Hub's own doc comment on why
// that's a real fact, not silence). A fact that could not be resolved
// (Provenance.Confidence != Deterministic) produces no node, the same
// "never guess" treatment every other mapper in this codebase applies -
// though in practice CollectSecurityHub never produces an Unresolved
// Hub (see its own doc comment on why).
func SecurityHubToIR(g *SecurityHubGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, h := range g.Hubs {
		if node, ok := mapHub(h); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapHub records h's subscription state verbatim (FR-5.9's
// measurement-not-verdict split: this mapper records whether Security
// Hub is subscribed and its auto-enable-controls setting, never whether
// the account's actual findings/standards posture is acceptable - a
// judgment FR-3.6's deferred findings half, and ultimately a backend
// predicate, would need to make).
func mapHub(h Hub) (ir.Node, bool) {
	if h.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	resource := h.HubARN
	if resource == "" {
		resource = "none"
	}

	return ir.Node{
		ID:            awsNodeID("securityhub", resource, "enablement"),
		ControlFamily: securityHubContinuousMonitoring.Family,
		Controls:      []ir.Control{securityHubContinuousMonitoring},
		Kind:          "aws_securityhub_hub",
		Attributes: map[string]string{
			"present":              strconv.FormatBool(h.Present),
			"subscribed_at":        h.SubscribedAt,
			"auto_enable_controls": strconv.FormatBool(h.AutoEnableControls),
		},
		Provenance:    h.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
