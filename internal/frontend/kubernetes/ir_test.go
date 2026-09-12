package kubernetes

import (
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

// TestToIRVendoredMinimalFixture is FR-5.8/5.9's mapping layer's own
// done criterion for Kubernetes: convert the real vendored fixture and
// check exactly the reviewed mappings fire.
func TestToIRVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal/k8s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if len(irGraph.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3 (pod securityContext, one container securityContext, one NetworkPolicy)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}
	deployAddr := ResourceAddress{APIVersion: "apps/v1", Kind: "Deployment", Name: "example-app"}

	pod, ok := byID[nodeID(deployAddr, "pod-security-context")]
	if !ok {
		t.Fatal("no pod securityContext node")
	}
	if pod.ControlFamily != "CM" || len(pod.Controls) != 1 || pod.Controls[0] != (ir.Control{Family: "CM", Base: 7}) {
		t.Errorf("pod securityContext node control = %+v/%+v, want CM/CM-7", pod.ControlFamily, pod.Controls)
	}
	if got, want := pod.Attributes["runAsNonRoot"], "true"; got != want {
		t.Errorf("runAsNonRoot = %q, want %q", got, want)
	}
	if got, want := pod.Attributes["seccompProfile.type"], "RuntimeDefault"; got != want {
		t.Errorf("seccompProfile.type = %q, want %q", got, want)
	}

	container, ok := byID[nodeID(deployAddr, "container-security-context[0]")]
	if !ok {
		t.Fatal("no container securityContext node")
	}
	if container.ControlFamily != "CM" || len(container.Controls) != 1 || container.Controls[0] != (ir.Control{Family: "CM", Base: 7}) {
		t.Errorf("container securityContext node control = %+v/%+v, want CM/CM-7", container.ControlFamily, container.Controls)
	}
	if got, want := container.Attributes["readOnlyRootFilesystem"], "true"; got != want {
		t.Errorf("readOnlyRootFilesystem = %q, want %q", got, want)
	}
	if got, want := container.Attributes["allowPrivilegeEscalation"], "false"; got != want {
		t.Errorf("allowPrivilegeEscalation = %q, want %q", got, want)
	}
	if got, want := container.Attributes["container_name"], "example-app"; got != want {
		t.Errorf("container_name = %q, want %q", got, want)
	}

	netpolAddr := ResourceAddress{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Name: "example-app-default-deny"}
	netpol, ok := byID[nodeID(netpolAddr, "default-deny")]
	if !ok {
		t.Fatal("no NetworkPolicy default-deny node")
	}
	if netpol.ControlFamily != "SC" || len(netpol.Controls) != 1 || netpol.Controls[0] != (ir.Control{Family: "SC", Base: 7, Enhancement: 5}) {
		t.Errorf("NetworkPolicy node control = %+v/%+v, want SC/SC-7(5)", netpol.ControlFamily, netpol.Controls)
	}
}

func TestMapPodSecurityContextSkipsResourceWithoutSecurityContext(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-security-context
spec:
  template:
    spec:
      containers:
        - name: app
          image: example:1.0
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0 (no securityContext anywhere to map)", len(irGraph.Nodes))
	}
}

// TestMapNetworkPolicyRejectsPolicyWithRules backs the mapping's own
// scoping: a NetworkPolicy that actually lists ingress/egress rules is
// a different posture than true default-deny and must not be mapped as
// one.
func TestMapNetworkPolicyRejectsPolicyWithRules(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allows-something
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0 (a NetworkPolicy with real rules is not default-deny)", len(irGraph.Nodes))
	}
}

// TestMapNetworkPolicyAcceptsExplicitEmptyRuleLists is a regression test:
// an earlier version of mapNetworkPolicyDefaultDeny checked only whether
// the "ingress"/"egress" keys were present in the spec, not whether their
// value actually listed a rule - so this explicit (and more auditable)
// spelling of default-deny was wrongly treated the same as a policy with
// real allow rules and left unmapped.
func TestMapNetworkPolicyAcceptsExplicitEmptyRuleLists(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: explicit-default-deny
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1 (explicit empty ingress/egress lists are still default-deny)", len(irGraph.Nodes))
	}
	if irGraph.Nodes[0].ControlFamily != "SC" {
		t.Errorf("ControlFamily = %q, want SC", irGraph.Nodes[0].ControlFamily)
	}
}

func TestMapNetworkPolicyRequiresBothPolicyTypes(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-only
spec:
  podSelector: {}
  policyTypes:
    - Ingress
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0 (only Ingress declared, not a full default-deny)", len(irGraph.Nodes))
	}
}

func TestToIRUnmappedKindProducesNoNodes(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
data:
  key: value
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	irGraph, err := ToIR(g)
	if err != nil {
		t.Fatalf("ToIR: %v", err)
	}
	if len(irGraph.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0 (ConfigMap has no reviewed mapping)", len(irGraph.Nodes))
	}
}
