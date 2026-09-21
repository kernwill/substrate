package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeSecurityGroups implements SecurityGroupsAPI by serving canned data
// loaded from this package's testdata fixtures (FR-3.10) instead of
// calling AWS.
type fakeSecurityGroups struct {
	groups []types.SecurityGroup
}

type fixturePermission struct {
	Protocol       string   `json:"protocol"`
	FromPort       *int32   `json:"from_port"`
	ToPort         *int32   `json:"to_port"`
	CIDRs          []string `json:"cidrs"`
	SourceGroupIDs []string `json:"source_group_ids"`
}

type fixtureSecurityGroup struct {
	GroupID string              `json:"group_id"`
	VpcID   string              `json:"vpc_id"`
	Ingress []fixturePermission `json:"ingress"`
	Egress  []fixturePermission `json:"egress"`
}

func loadFakeSecurityGroups(t *testing.T) *fakeSecurityGroups {
	t.Helper()
	var raw []fixtureSecurityGroup
	readTestdataJSON(t, "security_groups.json", &raw)

	toPermissions := func(fps []fixturePermission) []types.IpPermission {
		var perms []types.IpPermission
		for _, fp := range fps {
			p := types.IpPermission{
				IpProtocol: strPtr(fp.Protocol),
				FromPort:   fp.FromPort,
				ToPort:     fp.ToPort,
			}
			for _, cidr := range fp.CIDRs {
				cidr := cidr
				p.IpRanges = append(p.IpRanges, types.IpRange{CidrIp: &cidr})
			}
			for _, gid := range fp.SourceGroupIDs {
				gid := gid
				p.UserIdGroupPairs = append(p.UserIdGroupPairs, types.UserIdGroupPair{GroupId: &gid})
			}
			perms = append(perms, p)
		}
		return perms
	}

	f := &fakeSecurityGroups{}
	for _, g := range raw {
		f.groups = append(f.groups, types.SecurityGroup{
			GroupId:             strPtr(g.GroupID),
			VpcId:               strPtr(g.VpcID),
			IpPermissions:       toPermissions(g.Ingress),
			IpPermissionsEgress: toPermissions(g.Egress),
		})
	}
	return f
}

func (f *fakeSecurityGroups) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

func strPtr(s string) *string { return &s }

func TestCollectSecurityGroups(t *testing.T) {
	client := loadFakeSecurityGroups(t)
	graph, err := CollectSecurityGroups(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityGroups: %v", err)
	}

	// sg-open-ssh: 1 ingress rule, 1 CIDR -> 1 rule.
	// sg-restricted: 1 ingress rule x 2 CIDRs + 1 egress rule x 1 CIDR -> 3 rules.
	// sg-peer-only: 1 ingress rule with only a source-group reference, no
	// IPv4 CIDR -> 0 rules (deliberately out of scope for this pass).
	if len(graph.Rules) != 4 {
		t.Fatalf("got %d rules, want 4 (1 + 3 + 0)", len(graph.Rules))
	}

	byKey := make(map[string]SecurityGroupRule, len(graph.Rules))
	for _, r := range graph.Rules {
		byKey[r.SecurityGroupID+"|"+r.Direction+"|"+r.CIDR] = r
	}

	openSSH, ok := byKey["sg-open-ssh|ingress|0.0.0.0/0"]
	if !ok {
		t.Fatal("no sg-open-ssh ingress 0.0.0.0/0 rule")
	}
	if openSSH.Protocol != "tcp" || openSSH.FromPort == nil || *openSSH.FromPort != 22 || openSSH.ToPort == nil || *openSSH.ToPort != 22 {
		t.Errorf("sg-open-ssh rule = %+v, want tcp/22/22", openSSH)
	}
	if openSSH.VpcID != "vpc-1" {
		t.Errorf("sg-open-ssh.VpcID = %q, want vpc-1", openSSH.VpcID)
	}

	restrictedA, okA := byKey["sg-restricted|ingress|10.0.0.0/16"]
	restrictedB, okB := byKey["sg-restricted|ingress|10.1.0.0/16"]
	if !okA || !okB {
		t.Fatal("sg-restricted should produce one rule per CIDR in the same permission")
	}
	if restrictedA.Protocol != "tcp" || restrictedB.Protocol != "tcp" {
		t.Errorf("sg-restricted rules = %+v / %+v, want tcp", restrictedA, restrictedB)
	}

	egress, ok := byKey["sg-restricted|egress|0.0.0.0/0"]
	if !ok {
		t.Fatal("no sg-restricted egress 0.0.0.0/0 rule")
	}
	if egress.Protocol != "-1" || egress.FromPort != nil || egress.ToPort != nil {
		t.Errorf("sg-restricted egress rule = %+v, want protocol -1 with no port range", egress)
	}

	for _, r := range graph.Rules {
		if r.SecurityGroupID == "sg-peer-only" {
			t.Errorf("sg-peer-only produced a rule (%+v), want none - it has only a source-group reference, no IPv4 CIDR", r)
		}
	}
}

func TestCollectSecurityGroupsSorted(t *testing.T) {
	client := loadFakeSecurityGroups(t)
	graph, err := CollectSecurityGroups(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityGroups: %v", err)
	}
	for i := 1; i < len(graph.Rules); i++ {
		a, b := graph.Rules[i-1], graph.Rules[i]
		if a.SecurityGroupID > b.SecurityGroupID {
			t.Fatalf("rules not sorted by security group ID: %q after %q", a.SecurityGroupID, b.SecurityGroupID)
		}
	}
}

func TestCollectSecurityGroupsEveryRuleHasProvenance(t *testing.T) {
	client := loadFakeSecurityGroups(t)
	graph, err := CollectSecurityGroups(context.Background(), client, testObservedAt)
	if err != nil {
		t.Fatalf("CollectSecurityGroups: %v", err)
	}
	for _, r := range graph.Rules {
		if r.Provenance.Basis != "observed" {
			t.Errorf("%+v Provenance.Basis = %q, want observed", r, r.Provenance.Basis)
		}
	}
}
