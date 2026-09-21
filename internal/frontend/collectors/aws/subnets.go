package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/kernwill/substrate/internal/provenance"
)

// SubnetsCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const SubnetsCollectorVersion = "aws-subnets/v0.1.0"

// SubnetsAPI names only the EC2 operation this file's collector calls.
// See this package's doc.go for why this is a narrow, hand-written
// interface rather than the full *ec2.Client (FR-3.10's fixture-based
// testing).
type SubnetsAPI interface {
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
}

// Subnet is one collected VPC subnet - FR-3.4's topology half, scoped
// deliberately to the subnet's own attributes only. Whether a subnet is
// actually "public" depends on which route table governs it (including
// AWS's implicit main-route-table fallback for a subnet with no
// explicit association) and whether that route table has a route to an
// Internet Gateway - a real join this collector does not attempt yet,
// tracked as its own follow-on rather than guessed at here.
// MapPublicIPOnLaunch is still a real, independently meaningful SC-7
// fact on its own: it governs whether an instance launched in the
// subnet gets a public IPv4 address at all, regardless of routing.
type Subnet struct {
	SubnetID            string `json:"subnet_id"`
	VpcID               string `json:"vpc_id"`
	CIDR                string `json:"cidr"`
	AvailabilityZone    string `json:"availability_zone"`
	MapPublicIPOnLaunch bool   `json:"map_public_ip_on_launch"`

	Provenance provenance.Record `json:"provenance"`
}

// SubnetsGraph is every subnet found in the account/Region the caller's
// client is configured for.
type SubnetsGraph struct {
	Subnets []Subnet `json:"subnets"`
}

// CollectSubnets describes every subnet in the caller's account/Region -
// a single paginated call, the same no-fan-out shape
// CollectSecurityGroups uses (DescribeSubnets returns every attribute
// this collector needs inline, no second per-subnet call required).
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectSubnets(ctx context.Context, client SubnetsAPI, observedAt time.Time) (*SubnetsGraph, error) {
	paginator := ec2.NewDescribeSubnetsPaginator(client, &ec2.DescribeSubnetsInput{})
	var subnets []Subnet
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws: subnets: describe subnets: %w", err)
		}
		for _, s := range page.Subnets {
			if s.SubnetId == nil {
				continue
			}
			subnets = append(subnets, Subnet{
				SubnetID:            *s.SubnetId,
				VpcID:               valueOrEmpty(s.VpcId),
				CIDR:                valueOrEmpty(s.CidrBlock),
				AvailabilityZone:    valueOrEmpty(s.AvailabilityZone),
				MapPublicIPOnLaunch: s.MapPublicIpOnLaunch != nil && *s.MapPublicIpOnLaunch,
				Provenance:          subnetRecord(*s.SubnetId, observedAt),
			})
		}
	}

	sort.Slice(subnets, func(i, j int) bool { return subnets[i].SubnetID < subnets[j].SubnetID })
	return &SubnetsGraph{Subnets: subnets}, nil
}

// subnetRecord is a thin wrapper around this package's shared
// observedRecord (provenance.go), fixing this file's own collector
// version and locator parameter - same pattern as
// securityGroupRecord/s3Record. There is no unresolved case for this
// collector: DescribeSubnets either succeeds (every subnet it returns
// is fully resolved) or fails outright, which CollectSubnets already
// surfaces as a real error rather than a per-subnet Unresolved fact -
// the same reasoning securityGroupRecord's own doc comment gives.
func subnetRecord(subnetID string, observedAt time.Time) provenance.Record {
	return observedRecord(SubnetsCollectorVersion, "ec2:DescribeSubnets", map[string]string{"subnet_id": subnetID}, observedAt)
}
