package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// subnetBoundaryProtection is the control assignment for a VPC subnet's
// topology attributes, both the base attributes (mapSubnet) and the
// route-table join (mapSubnetRouting): base SC-7 (Boundary Protection),
// not an enhancement. Confirmed against the vendored FedRAMP dataset
// (internal/rules/data/fedramp-consolidated-rules.json) before
// proposing: sc-7 (base) is cited by KSI-CNA-ULN and KSI-SVC-EIS, ahead
// of sc-7.3 (Access Points, cited once) - the same dataset-citation-
// count discipline used to choose security groups over KMS/Config as
// the prior collector. Still base, not upgraded to an enhancement now
// that the routing join resolves whether a subnet has an Internet
// Gateway route (docs/adr/0008's subnets addendum): SC-7.3 (Access
// Points) requires evidence that external connections are limited to a
// *managed, monitored* set, which a single subnet's own routing fact
// doesn't establish on its own - this is a richer measurement under the
// same already-approved control, not grounds for a new mapping
// decision. Proposed and approved 2026-09-21 alongside this collector's
// first implementation.
var subnetBoundaryProtection = ir.Control{Family: "SC", Base: 7}

// SubnetsToIR converts g's subnets into IR nodes: one "topology" node
// per resolved subnet (mapSubnet), and one "routing" node per subnet
// whose route-table join also resolved (mapSubnetRouting) - two
// independently-provenanced facts, the same "independent facts get
// independent nodes" shape aws.CloudTrailToIR already establishes for
// audit-record-generation vs. log-file-validation. A fact that could
// not be resolved (Provenance.Confidence != Deterministic) produces no
// node - the same "never guess" treatment every other mapper in this
// codebase applies.
func SubnetsToIR(g *SubnetsGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, s := range g.Subnets {
		if node, ok := mapSubnet(s); ok {
			out.Nodes = append(out.Nodes, node)
		}
		if node, ok := mapSubnetRouting(s); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapSubnet records s's own attributes verbatim (FR-5.9's
// measurement-not-verdict split: this mapper records whether the
// subnet auto-assigns public IPs, never whether that combined with its
// actual routing makes it "public" - that combined judgment, if ever
// made, belongs in a backend predicate reading both this node and
// mapSubnetRouting's).
func mapSubnet(s Subnet) (ir.Node, bool) {
	if s.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	return ir.Node{
		ID:            awsNodeID("subnet", s.SubnetID, "topology"),
		ControlFamily: subnetBoundaryProtection.Family,
		Controls:      []ir.Control{subnetBoundaryProtection},
		Kind:          "aws_subnet",
		Attributes: map[string]string{
			"vpc_id":                  s.VpcID,
			"cidr":                    s.CIDR,
			"availability_zone":       s.AvailabilityZone,
			"map_public_ip_on_launch": strconv.FormatBool(s.MapPublicIPOnLaunch),
		},
		Provenance:    s.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}

// mapSubnetRouting records s.Routing's resolved route-table join
// verbatim - which route table governs the subnet and whether it has a
// route to an Internet Gateway, including that route's actual
// destination CIDR rather than assuming 0.0.0.0/0 (FR-5.9 again: record
// what was observed). Requires s.Routing itself to be non-nil AND
// Deterministic - a subnet whose governing route table this collector
// couldn't resolve at all produces no routing node, not a node
// asserting HasInternetGatewayRoute=false, which would be exactly the
// "collapsing unresolved into a negative" mistake
// aws.CollectS3's GetPublicAccessBlock nuance (docs/adr/0008) already
// warns against.
func mapSubnetRouting(s Subnet) (ir.Node, bool) {
	if s.Routing == nil || s.Routing.Provenance.Confidence != provenance.Deterministic {
		return ir.Node{}, false
	}

	attrs := map[string]string{
		"route_table_id":             s.Routing.RouteTableID,
		"has_internet_gateway_route": strconv.FormatBool(s.Routing.HasInternetGatewayRoute),
	}
	if s.Routing.HasInternetGatewayRoute {
		attrs["internet_gateway_route_destination"] = s.Routing.InternetGatewayRouteDestination
	}

	return ir.Node{
		ID:            awsNodeID("subnet", s.SubnetID, "routing"),
		ControlFamily: subnetBoundaryProtection.Family,
		Controls:      []ir.Control{subnetBoundaryProtection},
		Kind:          "aws_subnet_routing",
		Attributes:    attrs,
		Provenance:    s.Routing.Provenance,
		SchemaVersion: ir.SchemaVersion,
	}, true
}
