package aws

import (
	"fmt"
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// securityGroupDenyByDefault is the control assignment for one security
// group ingress/egress rule: SC-7(5) (Boundary Protection - Deny by
// Default, Allow by Exception), not the base control. This is not a
// guessed-at enhancement the way an IA-2 privilege-tier enhancement
// would be (compare aws.iamUserMFA's deliberate avoidance of
// IA-2(1)/(2)): a security group IS a deny-by-default, allow-by-exception
// construct - implicit deny-all, traffic permitted only by an explicit
// rule - so SC-7(5)'s own definition matches the collected fact directly,
// the same "the enhancement's definition matches the measurement, not a
// guess" reasoning okta.provisioningAutomatedAuditActions (AC-2(4)) and
// okta.adminRolePrivilegedAccounts (AC-6(5)) already established for
// this project. Confirmed against the vendored FedRAMP dataset
// (internal/rules/data/fedramp-consolidated-rules.json): sc-7.5 is cited
// by KSI-CNA-RNT ("Restricting Network Traffic") and KSI-CNA-MAT
// ("Minimizing Attack Surface"). Proposed and approved 2026-09-21
// alongside this collector's first implementation.
var securityGroupDenyByDefault = ir.Control{Family: "SC", Base: 7, Enhancement: 5}

// SecurityGroupsToIR converts g's rules into IR nodes, one per resolved
// rule. A rule whose fact could not be resolved (Provenance.Confidence
// != Deterministic) produces no node - the same "never guess" treatment
// every other mapper in this codebase applies, though in practice every
// rule CollectSecurityGroups produces is already Deterministic (see its
// own doc comment on why there's no per-rule unresolved case for this
// collector).
func SecurityGroupsToIR(g *SecurityGroupsGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, r := range g.Rules {
		if node, ok := mapSecurityGroupRule(r); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapSecurityGroupRule records r's protocol, port range, and CIDR
// verbatim as raw attributes (FR-5.9's measurement-not-verdict split:
// this mapper records what the rule permits, never whether that
// combination counts as an acceptable boundary posture - e.g. whether
// 0.0.0.0/0 on port 22 is a real risk depends on the resource behind
// the security group, a judgment a backend predicate makes, not this
// mapper).
func mapSecurityGroupRule(r SecurityGroupRule) (ir.Node, bool) {
	if r.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	aspect := fmt.Sprintf("%s-%s-%s-%s-%s", r.Direction, r.Protocol, portString(r.FromPort), portString(r.ToPort), r.CIDR)

	return ir.Node{
		ID:            awsNodeID("security-group", r.SecurityGroupID, aspect),
		ControlFamily: securityGroupDenyByDefault.Family,
		Controls:      []ir.Control{securityGroupDenyByDefault},
		Kind:          "aws_security_group_rule",
		Attributes: map[string]string{
			"vpc_id":    r.VpcID,
			"direction": r.Direction,
			"protocol":  r.Protocol,
			"from_port": portString(r.FromPort),
			"to_port":   portString(r.ToPort),
			"cidr":      r.CIDR,
		},
		Provenance:    r.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// portString renders a FromPort/ToPort pointer as "any" when nil (no
// port range - IpProtocol "-1", all protocols/ports) rather than a
// guessed numeric placeholder.
func portString(p *int32) string {
	if p == nil {
		return "any"
	}
	return strconv.Itoa(int(*p))
}
