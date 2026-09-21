package aws

import (
	"strconv"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// subnetBoundaryProtection is the control assignment for a VPC subnet's
// topology attributes: base SC-7 (Boundary Protection), not an
// enhancement. Confirmed against the vendored FedRAMP dataset
// (internal/rules/data/fedramp-consolidated-rules.json) before
// proposing: sc-7 (base) is cited by KSI-CNA-ULN and KSI-SVC-EIS, ahead
// of sc-7.3 (Access Points, cited once) - the same dataset-citation-
// count discipline used to choose security groups over KMS/Config as
// the prior collector. Base rather than an enhancement because this
// collector doesn't (yet) resolve the routing join that would justify
// a more specific claim - see Subnet's own doc comment on why
// MapPublicIPOnLaunch alone, without route-table/Internet-Gateway
// evidence, is the honest boundary this collector's facts support.
// Proposed and approved 2026-09-21 alongside this collector's first
// implementation.
var subnetBoundaryProtection = ir.Control{Family: "SC", Base: 7}

// SubnetsToIR converts g's subnets into IR nodes, one per resolved
// subnet. A subnet whose fact could not be resolved (Provenance.Confidence
// != Deterministic) produces no node - the same "never guess" treatment
// every other mapper in this codebase applies, though in practice every
// subnet CollectSubnets produces is already Deterministic (see its own
// doc comment on why there's no per-subnet unresolved case here).
func SubnetsToIR(g *SubnetsGraph) (ir.Graph, error) {
	var out ir.Graph
	for _, s := range g.Subnets {
		if node, ok := mapSubnet(s); ok {
			out.Nodes = append(out.Nodes, node)
		}
	}
	return out, nil
}

// mapSubnet records s's topology attributes verbatim (FR-5.9's
// measurement-not-verdict split: this mapper records whether the
// subnet auto-assigns public IPs, never whether that combined with its
// actual routing makes it "public" in the sense a backend predicate
// would need to judge - this collector doesn't resolve routing at all,
// see Subnet's own doc comment).
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
