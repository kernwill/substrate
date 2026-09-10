package kubernetes

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func writeYAML(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// initGitRepo commits everything currently in dir. Parse requires its
// input files to have git history (internal/frontend/vcs.CommitTime),
// so every test driving Parse against a scratch directory needs to be a
// real, committed git repo first.
func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=substrate-test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=substrate-test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "test fixture")
}

func resourceByAddress(t *testing.T, g *ResourceGraph, addr ResourceAddress) Resource {
	t.Helper()
	for _, r := range g.Resources {
		if r.Address == addr {
			return r
		}
	}
	t.Fatalf("no resource %s in graph (have %d resources)", addr, len(g.Resources))
	return Resource{}
}

// TestParseVendoredMinimalFixture is FR-2.4/FR-2.5's own done
// criterion: parse the real testdata/fixtures/minimal/k8s/deployment.yaml
// and check the resource graph captures both the Deployment's pod
// security context and the NetworkPolicy faithfully.
func TestParseVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal/k8s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(g.Resources))
	}

	dep := resourceByAddress(t, g, ResourceAddress{APIVersion: "apps/v1", Kind: "Deployment", Name: "example-app"})
	spec, ok := dep.Attributes["spec"].(map[string]any)
	if !ok {
		t.Fatalf("Deployment spec has type %T, want map[string]any", dep.Attributes["spec"])
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		t.Fatalf("spec.template has type %T, want map[string]any", spec["template"])
	}
	podSpec, ok := template["spec"].(map[string]any)
	if !ok {
		t.Fatalf("spec.template.spec has type %T, want map[string]any", template["spec"])
	}
	podSC, ok := podSpec["securityContext"].(map[string]any)
	if !ok {
		t.Fatalf("pod securityContext has type %T, want map[string]any", podSpec["securityContext"])
	}
	if got, want := podSC["runAsNonRoot"], true; got != want {
		t.Errorf("pod securityContext.runAsNonRoot = %v, want %v", got, want)
	}

	containers, ok := podSpec["containers"].([]any)
	if !ok || len(containers) != 1 {
		t.Fatalf("containers has type %T len %d, want a 1-element []any", podSpec["containers"], len(containers))
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		t.Fatalf("containers[0] has type %T, want map[string]any", containers[0])
	}
	containerSC, ok := container["securityContext"].(map[string]any)
	if !ok {
		t.Fatalf("container securityContext has type %T, want map[string]any", container["securityContext"])
	}
	if got, want := containerSC["readOnlyRootFilesystem"], true; got != want {
		t.Errorf("container securityContext.readOnlyRootFilesystem = %v, want %v", got, want)
	}
	if got, want := containerSC["allowPrivilegeEscalation"], false; got != want {
		t.Errorf("container securityContext.allowPrivilegeEscalation = %v, want %v", got, want)
	}

	netpol := resourceByAddress(t, g, ResourceAddress{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Name: "example-app-default-deny"})
	netSpec, ok := netpol.Attributes["spec"].(map[string]any)
	if !ok {
		t.Fatalf("NetworkPolicy spec has type %T, want map[string]any", netpol.Attributes["spec"])
	}
	policyTypes, ok := netSpec["policyTypes"].([]any)
	if !ok || len(policyTypes) != 2 {
		t.Fatalf("policyTypes = %v, want a 2-element list", netSpec["policyTypes"])
	}

	for _, r := range g.Resources {
		if err := r.Provenance.Validate(); err != nil {
			t.Errorf("resource %s has invalid Provenance: %v", r.Address, err)
		}
		if r.Provenance.Basis != "declared" {
			t.Errorf("resource %s Provenance.Basis = %q, want declared", r.Address, r.Provenance.Basis)
		}
	}
}

func TestParseClusterScopedObjectHasEmptyNamespace(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: example-role
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := resourceByAddress(t, g, ResourceAddress{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "example-role"})
	if r.Address.Namespace != "" {
		t.Errorf("Namespace = %q, want empty for a cluster-scoped object", r.Address.Namespace)
	}
}

func TestParseNamespacedObjectCapturesNamespace(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
  namespace: example-ns
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := resourceByAddress(t, g, ResourceAddress{APIVersion: "v1", Kind: "ConfigMap", Namespace: "example-ns", Name: "example-config"})
	if r.Address.Namespace != "example-ns" {
		t.Errorf("Namespace = %q, want example-ns", r.Address.Namespace)
	}
}

func TestParseRejectsMissingAPIVersion(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
kind: ConfigMap
metadata:
  name: example-config
`)
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on a document missing apiVersion, want error")
	}
}

func TestParseRejectsMissingKind(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
metadata:
  name: example-config
`)
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on a document missing kind, want error")
	}
}

func TestParseRejectsMissingName(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata: {}
`)
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on a document missing metadata.name, want error")
	}
}

func TestParseRejectsMissingMetadata(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
`)
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on a document missing metadata entirely, want error")
	}
}

func TestParseRejectsSyntaxError(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", "apiVersion: v1\nkind: [unterminated")
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on malformed YAML, want error")
	}
}

func TestParseRejectsDuplicateAddress(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
`)
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on a duplicate object address, want error")
	}
}

func TestParseSkipsEmptyDocuments(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `---
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
---
---
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(g.Resources))
	}
}

func TestParseMultiDocumentFile(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: b
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(g.Resources))
	}
}

func TestParseIsOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "z.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: z
`)
	writeYAML(t, dir, "a.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: a
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(g.Resources))
	}
	if g.Resources[0].Address.Name != "a" || g.Resources[1].Address.Name != "z" {
		t.Errorf("resources not sorted by address: got %s, %s", g.Resources[0].Address, g.Resources[1].Address)
	}
}

func TestParseHandlesYmlExtension(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(g.Resources))
	}
}

func TestParseIgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "main.yaml", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: example-config
`)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not yaml"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(g.Resources))
	}
}
