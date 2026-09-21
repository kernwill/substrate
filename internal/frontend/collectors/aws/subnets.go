package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// SubnetsCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const SubnetsCollectorVersion = "aws-subnets/v0.1.0"

// SubnetsAPI names the two EC2 operations this file's collector calls.
// See this package's doc.go for why this is a narrow, hand-written
// interface rather than the full *ec2.Client (FR-3.10's fixture-based
// testing).
//
// DescribeRouteTables is the join this collector's first version
// deferred (docs/adr/0008's own note on it): resolving whether a subnet
// is actually routable to the internet needs the subnet's governing
// route table - its explicit association if it has one, AWS's implicit
// main-route-table fallback if it doesn't - and whether that table has
// a route to an Internet Gateway. See Routing's own doc comment for how
// that join is recorded.
type SubnetsAPI interface {
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeRouteTables(ctx context.Context, params *ec2.DescribeRouteTablesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
}

// Subnet is one collected VPC subnet - FR-3.4's topology half.
// MapPublicIPOnLaunch is a real, independently meaningful SC-7 fact on
// its own (it governs whether an instance launched in the subnet gets a
// public IPv4 address at all), resolved directly from DescribeSubnets
// and never nil. Routing is a separate, independently-provenanced fact
// (see its own doc comment) - nil only when this collector could not
// resolve which route table governs the subnet at all, never as a
// stand-in for "no route to the internet," which is instead
// Routing.HasInternetGatewayRoute == false, a real resolved measurement.
type Subnet struct {
	SubnetID            string `json:"subnet_id"`
	VpcID               string `json:"vpc_id"`
	CIDR                string `json:"cidr"`
	AvailabilityZone    string `json:"availability_zone"`
	MapPublicIPOnLaunch bool   `json:"map_public_ip_on_launch"`

	Provenance provenance.Record `json:"provenance"`

	Routing *SubnetRouting `json:"routing"`
}

// SubnetRouting is the completed half of the join docs/adr/0008's
// subnets addendum deferred: which route table governs this subnet
// (RouteTableID - its explicit association, or the VPC's main route
// table if it has none) and whether that table has a route to an
// Internet Gateway (a GatewayId prefixed "igw-"). InternetGatewayRouteDestination
// is the actual destination CIDR of that route, recorded rather than
// assumed to be 0.0.0.0/0 - FR-5.9's "record the measurement, not an
// interpretation of it" applied here the same way Subnet's own
// MapPublicIPOnLaunch doc comment applies it to a simpler field.
//
// This is a separate provenanced fact from Subnet's own base attributes,
// not a field on it directly - the same "independent facts, independent
// Provenance" shape aws.Bucket's Encryption/PublicAccessBlock/Logging
// sub-structs already establish, so a route-table resolution failure
// (a subnet with neither an explicit association nor a resolvable VPC
// main table, which real AWS accounts should never actually produce,
// but this collector does not assume) never has to silently corrupt or
// withhold the subnet's own already-resolved CIDR/AZ/MapPublicIPOnLaunch
// facts.
type SubnetRouting struct {
	RouteTableID                    string `json:"route_table_id"`
	HasInternetGatewayRoute         bool   `json:"has_internet_gateway_route"`
	InternetGatewayRouteDestination string `json:"internet_gateway_route_destination,omitempty"`

	Provenance provenance.Record `json:"provenance"`
}

// SubnetsGraph is every subnet found in the account/Region the caller's
// client is configured for.
type SubnetsGraph struct {
	Subnets []Subnet `json:"subnets"`
}

// CollectSubnets describes every subnet and every route table in the
// caller's account/Region - two single paginated calls, the same
// no-fan-out shape CollectSecurityGroups uses - then joins each subnet
// to its governing route table to resolve SubnetRouting.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectSubnets(ctx context.Context, client SubnetsAPI, observedAt time.Time) (*SubnetsGraph, error) {
	rawSubnets, err := describeSubnets(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: subnets: describe subnets: %w", err)
	}
	routeTables, err := describeRouteTables(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: subnets: describe route tables: %w", err)
	}
	bySubnetID, mainByVpcID := indexRouteTables(routeTables)

	subnets := make([]Subnet, 0, len(rawSubnets))
	for _, s := range rawSubnets {
		if s.SubnetId == nil {
			continue
		}
		subnet := Subnet{
			SubnetID:            *s.SubnetId,
			VpcID:               valueOrEmpty(s.VpcId),
			CIDR:                valueOrEmpty(s.CidrBlock),
			AvailabilityZone:    valueOrEmpty(s.AvailabilityZone),
			MapPublicIPOnLaunch: s.MapPublicIpOnLaunch != nil && *s.MapPublicIpOnLaunch,
			Provenance:          subnetRecord(*s.SubnetId, observedAt),
		}
		subnet.Routing = resolveSubnetRouting(subnet.SubnetID, subnet.VpcID, bySubnetID, mainByVpcID, observedAt)
		subnets = append(subnets, subnet)
	}

	sort.Slice(subnets, func(i, j int) bool { return subnets[i].SubnetID < subnets[j].SubnetID })
	return &SubnetsGraph{Subnets: subnets}, nil
}

func describeSubnets(ctx context.Context, client SubnetsAPI) ([]types.Subnet, error) {
	paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	var subnets []types.Subnet
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, page.Subnets...)
	}
	return subnets, nil
}

func describeRouteTables(ctx context.Context, client SubnetsAPI) ([]types.RouteTable, error) {
	paginator := ec2.NewDescribeRouteTablesPaginator(client, &ec2.DescribeRouteTablesInput{})
	var tables []types.RouteTable
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		tables = append(tables, page.RouteTables...)
	}
	return tables, nil
}

// indexRouteTables builds the two lookups resolveSubnetRouting needs:
// bySubnetID for a subnet's explicit route table association, and
// mainByVpcID for the VPC's main (default) route table, which governs
// any subnet with no explicit association of its own - AWS's own
// documented fallback behavior, not this package's invention.
func indexRouteTables(tables []types.RouteTable) (bySubnetID map[string]types.RouteTable, mainByVpcID map[string]types.RouteTable) {
	bySubnetID = make(map[string]types.RouteTable)
	mainByVpcID = make(map[string]types.RouteTable)
	for _, rt := range tables {
		for _, assoc := range rt.Associations {
			if assoc.SubnetId != nil {
				bySubnetID[*assoc.SubnetId] = rt
			}
			if assoc.Main != nil && *assoc.Main {
				mainByVpcID[valueOrEmpty(rt.VpcId)] = rt
			}
		}
	}
	return bySubnetID, mainByVpcID
}

// resolveSubnetRouting finds subnetID's governing route table (explicit
// association first, the VPC's main table as fallback) and checks it
// for a route to an Internet Gateway. Returns a SubnetRouting with
// Provenance.Confidence Unresolved - not a nil pointer, per this
// package's own "always record a fact, resolved or not" discipline -
// if neither lookup finds a route table at all, which a well-formed AWS
// account should never actually produce (every subnet has an explicit
// or inherited main route table) but this collector does not assume.
func resolveSubnetRouting(subnetID, vpcID string, bySubnetID, mainByVpcID map[string]types.RouteTable, observedAt time.Time) *SubnetRouting {
	const api = "ec2:DescribeRouteTables"
	rt, ok := bySubnetID[subnetID]
	if !ok {
		rt, ok = mainByVpcID[vpcID]
	}
	if !ok {
		return &SubnetRouting{
			Provenance: subnetRoutingUnresolvedRecord(subnetID, api, "no explicit or main route table found for this subnet", observedAt),
		}
	}

	routing := &SubnetRouting{
		RouteTableID: valueOrEmpty(rt.RouteTableId),
		Provenance:   subnetRoutingRecord(subnetID, api, observedAt),
	}
	for _, route := range rt.Routes {
		if route.GatewayId != nil && strings.HasPrefix(*route.GatewayId, "igw-") {
			routing.HasInternetGatewayRoute = true
			routing.InternetGatewayRouteDestination = valueOrEmpty(route.DestinationCidrBlock)
			break
		}
	}
	return routing
}

// subnetRecord and subnetRoutingRecord/subnetRoutingUnresolvedRecord are
// thin wrappers around this package's shared observedRecord/
// unresolvedRecord (provenance.go), fixing this file's own collector
// version and locator parameters - same pattern as
// securityGroupRecord/s3Record.
func subnetRecord(subnetID string, observedAt time.Time) provenance.Record {
	return observedRecord(SubnetsCollectorVersion, "ec2:DescribeSubnets", map[string]string{"subnet_id": subnetID}, observedAt)
}

func subnetRoutingRecord(subnetID, api string, observedAt time.Time) provenance.Record {
	return observedRecord(SubnetsCollectorVersion, api, map[string]string{"subnet_id": subnetID}, observedAt)
}

func subnetRoutingUnresolvedRecord(subnetID, api, reason string, observedAt time.Time) provenance.Record {
	return unresolvedRecord(SubnetsCollectorVersion, api, reason, map[string]string{"subnet_id": subnetID}, observedAt)
}
