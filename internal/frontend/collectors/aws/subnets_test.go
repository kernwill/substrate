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
	subnets []types.Subnet
}

type fixtureSubnet struct {
	SubnetID            string `json:"subnet_id"`
	VpcID               string `json:"vpc_id"`
	CIDR                string `json:"cidr"`
	AvailabilityZone    string `json:"availability_zone"`
	MapPublicIPOnLaunch bool   `json:"map_public_ip_on_launch"`
}

func loadFakeSubnets(t *testing.T) *fakeSubnets {
	t.Helper()
	var raw []fixtureSubnet
	readTestdataJSON(t, "subnets.json", &raw)

	f := &fakeSubnets{}
	for _, s := range raw {
		mapPublic := s.MapPublicIPOnLaunch
		f.subnets = append(f.subnets, types.Subnet{
			SubnetId:            strPtr(s.SubnetID),
			VpcId:               strPtr(s.VpcID),
			CidrBlock:           strPtr(s.CIDR),
			AvailabilityZone:    strPtr(s.AvailabilityZone),
			MapPublicIpOnLaunch: &mapPublic,
		})
	}
	return f
}

func (f *fakeSubnets) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return &ec2.DescribeSubnetsOutput{Subnets: f.subnets}, nil
}

func TestCollectSubnets(t *testing.T) {
	client := loadFakeSubnets(t)
	graph, err := CollectSubnets(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSubnets: %v", err)
	}
	if len(graph.Subnets) != 2 {
		t.Fatalf("got %d subnets, want 2", len(graph.Subnets))
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

	priv := byID["subnet-private"]
	if priv.MapPublicIPOnLaunch {
		t.Error("subnet-private.MapPublicIPOnLaunch = true, want false (a resolved false, not an absence)")
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
