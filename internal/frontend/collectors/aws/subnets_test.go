package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeSubnets implements SubnetsAPI by serving canned data loaded from
// this package's testdata fixtures (FR-3.10) instead of calling AWS.
type fakeSubnets struct {
	subnets     []types.Subnet
	routeTables []types.RouteTable
}

type fixtureSubnet struct {
	SubnetID            string `json:"subnet_id"`
	VpcID               string `json:"vpc_id"`
	CIDR                string `json:"cidr"`
	AvailabilityZone    string `json:"availability_zone"`
	MapPublicIPOnLaunch bool   `json:"map_public_ip_on_launch"`
}

type fixtureRoute struct {
	GatewayID       string `json:"gateway_id"`
	DestinationCIDR string `json:"destination_cidr"`
}

type fixtureRouteTableAssociation struct {
	SubnetID string `json:"subnet_id"`
	Main     bool   `json:"main"`
}

type fixtureRouteTable struct {
	RouteTableID string                         `json:"route_table_id"`
	VpcID        string                         `json:"vpc_id"`
	Associations []fixtureRouteTableAssociation `json:"associations"`
	Routes       []fixtureRoute                 `json:"routes"`
}

func loadFakeSubnets(t *testing.T) *fakeSubnets {
	t.Helper()
	var rawSubnets []fixtureSubnet
	readTestdataJSON(t, "subnets.json", &rawSubnets)
	var rawRouteTables []fixtureRouteTable
	readTestdataJSON(t, "route_tables.json", &rawRouteTables)

	f := &fakeSubnets{}
	for _, s := range rawSubnets {
		mapPublic := s.MapPublicIPOnLaunch
		f.subnets = append(f.subnets, types.Subnet{
			SubnetId:            strPtr(s.SubnetID),
			VpcId:               strPtr(s.VpcID),
			CidrBlock:           strPtr(s.CIDR),
			AvailabilityZone:    strPtr(s.AvailabilityZone),
			MapPublicIpOnLaunch: &mapPublic,
		})
	}
	for _, rt := range rawRouteTables {
		table := types.RouteTable{
			RouteTableId: strPtr(rt.RouteTableID),
			VpcId:        strPtr(rt.VpcID),
		}
		for _, a := range rt.Associations {
			assoc := types.RouteTableAssociation{Main: boolPtr(a.Main)}
			if a.SubnetID != "" {
				assoc.SubnetId = strPtr(a.SubnetID)
			}
			table.Associations = append(table.Associations, assoc)
		}
		for _, r := range rt.Routes {
			table.Routes = append(table.Routes, types.Route{
				GatewayId:            strPtr(r.GatewayID),
				DestinationCidrBlock: strPtr(r.DestinationCIDR),
			})
		}
		f.routeTables = append(f.routeTables, table)
	}
	return f
}

func (f *fakeSubnets) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return &ec2.DescribeSubnetsOutput{Subnets: f.subnets}, nil
}

func (f *fakeSubnets) DescribeRouteTables(ctx context.Context, params *ec2.DescribeRouteTablesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return &ec2.DescribeRouteTablesOutput{RouteTables: f.routeTables}, nil
}

func TestCollectSubnets(t *testing.T) {
	client := loadFakeSubnets(t)
	graph, err := CollectSubnets(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSubnets: %v", err)
	}
	if len(graph.Subnets) != 4 {
		t.Fatalf("got %d subnets, want 4", len(graph.Subnets))
	}

	byID := make(map[string]Subnet, len(graph.Subnets))
	for _, s := range graph.Subnets {
		byID[s.SubnetID] = s
	}

	pub := byID["subnet-public"]
	if pub.Provenance.Confidence != "deterministic" {
		t.Fatalf("subnet-public.Provenance.Confidence = %v, want deterministic", pub.Provenance.Confidence)
	}
	if !pub.MapPublicIPOnLaunch {
		t.Error("subnet-public.MapPublicIPOnLaunch = false, want true")
	}
	if pub.CIDR != "10.0.1.0/24" || pub.VpcID != "vpc-1" || pub.AvailabilityZone != "us-east-1a" {
		t.Errorf("subnet-public = %+v, want cidr 10.0.1.0/24, vpc-1, us-east-1a", pub)
	}
	if pub.Routing == nil || pub.Routing.Provenance.Confidence != "deterministic" {
		t.Fatalf("subnet-public.Routing = %+v, want resolved", pub.Routing)
	}
	if pub.Routing.RouteTableID != "rt-public" {
		t.Errorf("subnet-public.Routing.RouteTableID = %q, want rt-public", pub.Routing.RouteTableID)
	}
	if !pub.Routing.HasInternetGatewayRoute {
		t.Error("subnet-public.Routing.HasInternetGatewayRoute = false, want true (explicit association to rt-public, which has an igw- route)")
	}
	if pub.Routing.InternetGatewayRouteDestination != "0.0.0.0/0" {
		t.Errorf("subnet-public.Routing.InternetGatewayRouteDestination = %q, want 0.0.0.0/0", pub.Routing.InternetGatewayRouteDestination)
	}

	priv := byID["subnet-private"]
	if priv.MapPublicIPOnLaunch {
		t.Error("subnet-private.MapPublicIPOnLaunch = true, want false (a resolved false, not an absence)")
	}
	if priv.Routing == nil || priv.Routing.Provenance.Confidence != "deterministic" {
		t.Fatalf("subnet-private.Routing = %+v, want resolved", priv.Routing)
	}
	if priv.Routing.HasInternetGatewayRoute {
		t.Error("subnet-private.Routing.HasInternetGatewayRoute = true, want false (rt-private has no igw- route, only a NAT gateway)")
	}

	fallback := byID["subnet-fallback"]
	if fallback.Routing == nil || fallback.Routing.Provenance.Confidence != "deterministic" {
		t.Fatalf("subnet-fallback.Routing = %+v, want resolved via the VPC main route table fallback", fallback.Routing)
	}
	if fallback.Routing.RouteTableID != "rt-main" {
		t.Errorf("subnet-fallback.Routing.RouteTableID = %q, want rt-main (no explicit association, falls back to the VPC's main table)", fallback.Routing.RouteTableID)
	}
	if !fallback.Routing.HasInternetGatewayRoute {
		t.Error("subnet-fallback.Routing.HasInternetGatewayRoute = false, want true (rt-main has an igw- route)")
	}

	orphan := byID["subnet-orphan"]
	if orphan.Routing == nil {
		t.Fatal("subnet-orphan.Routing is nil, want a non-nil Unresolved fact (never a bare nil - see Subnet's own doc comment)")
	}
	if orphan.Routing.Provenance.Confidence != "unresolved" {
		t.Errorf("subnet-orphan.Routing.Provenance.Confidence = %v, want unresolved (vpc-2 has no route table at all in this fixture)", orphan.Routing.Provenance.Confidence)
	}
	if orphan.Routing.Provenance.UnresolvedReason == "" {
		t.Error("subnet-orphan.Routing.Provenance.UnresolvedReason is empty")
	}
}

func TestCollectSubnetsSorted(t *testing.T) {
	client := loadFakeSubnets(t)
	graph, err := CollectSubnets(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSubnets: %v", err)
	}
	for i := 1; i < len(graph.Subnets); i++ {
		if graph.Subnets[i-1].SubnetID >= graph.Subnets[i].SubnetID {
			t.Fatalf("subnets not sorted: %q >= %q", graph.Subnets[i-1].SubnetID, graph.Subnets[i].SubnetID)
		}
	}
}
