package aws

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/kernwill/substrate/internal/provenance"
)

// SecurityGroupsCollectorVersion is this file's own collector version
// (FR-4.1), independent of every other collector version in this
// package.
const SecurityGroupsCollectorVersion = "aws-security-groups/v0.1.0"

// SecurityGroupsAPI names only the EC2 operation this file's collector
// calls. See this package's doc.go for why this is a narrow,
// hand-written interface rather than the full *ec2.Client (FR-3.10's
// fixture-based testing).
type SecurityGroupsAPI interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// SecurityGroupRule is one collected security group rule - one IPv4
// CIDR range in one ingress or egress permission entry of one security
// group. AWS's own API nests CIDR ranges inside a "permission" shape
// (protocol plus port range) inside a security group; this collector
// flattens that fully so each (security group, direction, protocol,
// port range, CIDR) combination is its own independently-provenanced
// fact - the granularity a future "is 0.0.0.0/0 open on port 22"
// predicate needs to check directly, not reconstruct from AWS's nested
// response shape.
//
// FromPort/ToPort are nil when the permission doesn't carry a port
// range at all (IpProtocol "-1", all protocols/ports) - a real
// "not applicable," not a guessed 0. For icmp/icmpv6, AWS overloads
// these fields as ICMP type/code rather than a port number; this
// collector records whatever AWS returned verbatim and does not
// reinterpret it per protocol (FR-5.9: store the measurement, not an
// interpretation of it).
//
// Scoped deliberately to IPv4 CIDR ranges only for this first pass -
// IPv6 ranges (Ipv6Ranges) and cross-security-group references
// (UserIdGroupPairs) are real AWS rule sources this struct does not
// yet model at all, a narrower-than-complete first cut in the same
// spirit as CloudTrail's retention gap (docs/adr/0008): worth revisiting
// as its own follow-on rather than guessed at or silently dropped here.
type SecurityGroupRule struct {
	SecurityGroupID string `json:"security_group_id"`
	VpcID           string `json:"vpc_id"`
	// Direction is "ingress" or "egress".
	Direction string `json:"direction"`
	// Protocol is AWS's own IpProtocol value verbatim: "tcp", "udp",
	// "icmp", "icmpv6", a protocol number, or "-1" for all protocols.
	Protocol string `json:"protocol"`
	FromPort *int32 `json:"from_port,omitempty"`
	ToPort   *int32 `json:"to_port,omitempty"`
	CIDR     string `json:"cidr"`

	Provenance provenance.Record `json:"provenance"`
}

// SecurityGroupsGraph is every IPv4 ingress/egress rule found across
// every security group in the account/Region the caller's client is
// configured for.
type SecurityGroupsGraph struct {
	Rules []SecurityGroupRule `json:"rules"`
}

// CollectSecurityGroups describes every security group in the caller's
// account/Region and flattens each one's ingress and egress IPv4 rules
// into SecurityGroupRule facts. Unlike S3/IAM's per-item fan-out,
// DescribeSecurityGroups already returns every rule inline - no second,
// per-security-group API call is needed, the same single-call shape
// aws.describeTrails uses for CloudTrail.
//
// observedAt is stamped as every resulting fact's Provenance.Timestamp -
// never derived from time.Now() here, matching every other collector in
// this package (FR-5.3).
func CollectSecurityGroups(ctx context.Context, client SecurityGroupsAPI, observedAt time.Time) (*SecurityGroupsGraph, error) {
	groups, err := describeSecurityGroups(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("aws: security-groups: describe security groups: %w", err)
	}

	var rules []SecurityGroupRule
	for _, g := range groups {
		if g.GroupId == nil {
			continue
		}
		rules = append(rules, flattenPermissions(*g.GroupId, valueOrEmpty(g.VpcId), "ingress", g.IpPermissions, observedAt)...)
		rules = append(rules, flattenPermissions(*g.GroupId, valueOrEmpty(g.VpcId), "egress", g.IpPermissionsEgress, observedAt)...)
	}

	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.SecurityGroupID != b.SecurityGroupID {
			return a.SecurityGroupID < b.SecurityGroupID
		}
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.CIDR < b.CIDR
	})

	return &SecurityGroupsGraph{Rules: rules}, nil
}

// describeSecurityGroups pages through every security group in the
// account/Region, sorted by ID for the same reproducibility reasons
// listBucketNames documents (s3.go).
func describeSecurityGroups(ctx context.Context, client SecurityGroupsAPI) ([]types.SecurityGroup, error) {
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	var groups []types.SecurityGroup
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, page.SecurityGroups...)
	}
	sort.Slice(groups, func(i, j int) bool { return valueOrEmpty(groups[i].GroupId) < valueOrEmpty(groups[j].GroupId) })
	return groups, nil
}

// flattenPermissions expands one direction's []IpPermission into one
// SecurityGroupRule per IPv4 CIDR range - a permission with three CIDR
// ranges produces three rules, each independently provenanced, not one
// rule carrying a list.
func flattenPermissions(groupID, vpcID, direction string, perms []types.IpPermission, observedAt time.Time) []SecurityGroupRule {
	var rules []SecurityGroupRule
	for _, p := range perms {
		protocol := valueOrEmpty(p.IpProtocol)
		for _, r := range p.IpRanges {
			if r.CidrIp == nil {
				continue
			}
			rules = append(rules, SecurityGroupRule{
				SecurityGroupID: groupID,
				VpcID:           vpcID,
				Direction:       direction,
				Protocol:        protocol,
				FromPort:        p.FromPort,
				ToPort:          p.ToPort,
				CIDR:            *r.CidrIp,
				Provenance:      securityGroupRecord(groupID, direction, observedAt),
			})
		}
	}
	return rules
}

// securityGroupRecord is a thin wrapper around this package's shared
// observedRecord (provenance.go), fixing this file's own collector
// version and locator parameters - same pattern as s3Record/iamRecord.
// There is no unresolved case for this collector: DescribeSecurityGroups
// either succeeds (every rule it returns is fully resolved, AWS never
// returns a partial IpPermission) or fails outright, which
// CollectSecurityGroups already surfaces as a real error rather than a
// per-rule Unresolved fact.
func securityGroupRecord(groupID, direction string, observedAt time.Time) provenance.Record {
	return observedRecord(SecurityGroupsCollectorVersion, "ec2:DescribeSecurityGroups", map[string]string{"security_group_id": groupID, "direction": direction}, observedAt)
}

func valueOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
