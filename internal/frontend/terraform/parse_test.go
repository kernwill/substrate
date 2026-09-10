package terraform

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func writeTF(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// initGitRepo commits everything currently in dir. Parse requires its
// input files to have git history (gitCommitTime, parse.go), so every
// test driving Parse against a scratch directory needs to be a real,
// committed git repo first - the same requirement a real customer's
// Terraform directory needs to meet.
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

// TestParseVendoredMinimalFixture is FR-2.1's own done criterion: parse
// the real testdata/fixtures/minimal/main.tf and check the resource
// graph is exactly right - literals resolved, nested blocks flattened
// into nested AttributeValues, and cross-resource references detected
// as both an Unresolved attribute and a Reference.
func TestParseVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(g.Resources) != 4 {
		t.Fatalf("got %d resources, want 4", len(g.Resources))
	}

	bucket := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket", Name: "example"})
	if got, want := bucket.Attributes["bucket"].Value, "substrate-minimal-fixture-example"; got != want {
		t.Errorf("aws_s3_bucket.example.bucket = %v, want %v", got, want)
	}
	if len(bucket.References) != 0 {
		t.Errorf("aws_s3_bucket.example has %d references, want 0", len(bucket.References))
	}

	versioning := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket_versioning", Name: "example"})
	bucketAttr := versioning.Attributes["bucket"]
	if bucketAttr.Value != nil || bucketAttr.Unresolved == "" {
		t.Errorf("aws_s3_bucket_versioning.example.bucket = %+v, want Unresolved set and Value nil", bucketAttr)
	}
	if len(versioning.References) != 1 {
		t.Fatalf("aws_s3_bucket_versioning.example has %d references, want 1", len(versioning.References))
	}
	wantRef := Reference{Attribute: "bucket", Target: ResourceAddress{Type: "aws_s3_bucket", Name: "example"}, TargetAttribute: "id"}
	if versioning.References[0] != wantRef {
		t.Errorf("reference = %+v, want %+v", versioning.References[0], wantRef)
	}
	nestedBlock, ok := versioning.Attributes["versioning_configuration"].Value.(map[string]AttributeValue)
	if !ok {
		t.Fatalf("versioning_configuration value has type %T, want map[string]AttributeValue", versioning.Attributes["versioning_configuration"].Value)
	}
	if got, want := nestedBlock["status"].Value, "Enabled"; got != want {
		t.Errorf("versioning_configuration.status = %v, want %v", got, want)
	}

	sse := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket_server_side_encryption_configuration", Name: "example"})
	rule, ok := sse.Attributes["rule"].Value.(map[string]AttributeValue)
	if !ok {
		t.Fatalf("rule value has type %T, want map[string]AttributeValue", sse.Attributes["rule"].Value)
	}
	inner, ok := rule["apply_server_side_encryption_by_default"].Value.(map[string]AttributeValue)
	if !ok {
		t.Fatalf("apply_server_side_encryption_by_default value has type %T, want map[string]AttributeValue", rule["apply_server_side_encryption_by_default"].Value)
	}
	if got, want := inner["sse_algorithm"].Value, "aws:kms"; got != want {
		t.Errorf("rule.apply_server_side_encryption_by_default.sse_algorithm = %v, want %v", got, want)
	}

	pab := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket_public_access_block", Name: "example"})
	for _, attr := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		if got, want := pab.Attributes[attr].Value, true; got != want {
			t.Errorf("aws_s3_bucket_public_access_block.example.%s = %v, want %v", attr, got, want)
		}
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

func TestParseResolvesVariableDefault(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
variable "bucket_name" {
  default = "my-bucket"
}

resource "aws_s3_bucket" "example" {
  bucket = var.bucket_name
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket", Name: "example"})
	if got, want := r.Attributes["bucket"].Value, "my-bucket"; got != want {
		t.Errorf("bucket = %v, want %v", got, want)
	}
}

func TestParseVariableWithoutDefaultIsUnresolved(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
variable "bucket_name" {}

resource "aws_s3_bucket" "example" {
  bucket = var.bucket_name
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket", Name: "example"})
	attr := r.Attributes["bucket"]
	if attr.Value != nil || attr.Unresolved == "" {
		t.Errorf("bucket = %+v, want Unresolved set", attr)
	}
}

func TestParseDataSourceReferenceIsUnresolved(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_instance" "example" {
  ami = data.aws_ami.example.id
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := resourceByAddress(t, g, ResourceAddress{Type: "aws_instance", Name: "example"})
	attr := r.Attributes["ami"]
	if attr.Value != nil || attr.Unresolved == "" {
		t.Errorf("ami = %+v, want Unresolved set", attr)
	}
	if len(r.References) != 0 {
		t.Errorf("got %d references, want 0 (a data source reference is not a resource-graph edge)", len(r.References))
	}
}

func TestParseInterpolatedExpressionIsUnresolved(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "a" {
  bucket = "a"
}

resource "aws_s3_bucket" "b" {
  bucket = "${aws_s3_bucket.a.id}-suffix"
}
`)
	initGitRepo(t, dir)
	g, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := resourceByAddress(t, g, ResourceAddress{Type: "aws_s3_bucket", Name: "b"})
	attr := r.Attributes["bucket"]
	if attr.Value != nil || attr.Unresolved == "" {
		t.Errorf("bucket = %+v, want Unresolved set (interpolation combines a reference with other content)", attr)
	}
}

func TestParseRejectsDuplicateResourceAddress(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "example" {
  bucket = "a"
}

resource "aws_s3_bucket" "example" {
  bucket = "b"
}
`)
	initGitRepo(t, dir)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on duplicate resource address, want error")
	}
}

func TestParseRejectsSyntaxError(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `resource "aws_s3_bucket" "example" {`)
	if _, err := Parse(dir); err == nil {
		t.Error("Parse succeeded on malformed HCL, want error")
	}
}

// TestParseIsOrderIndependent backs Parse's own doc comment: resources
// come back sorted by address regardless of declaration order or which
// file they're declared in.
func TestParseIsOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "z.tf", `
resource "aws_s3_bucket" "z" {
  bucket = "z"
}
`)
	writeTF(t, dir, "a.tf", `
resource "aws_s3_bucket" "a" {
  bucket = "a"
}
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

func TestParseIgnoresNonTerraformFiles(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "example" {
  bucket = "a"
}
`)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not terraform"), 0o644); err != nil {
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

// TestParseTimestampTracksGitCommitNotModTime is a regression test for a
// real reproducibility bug caught by manually reviewing a regenerated
// golden fixture's diff before accepting it (see docs/adr/0006): an
// earlier version of this package used the file's filesystem
// modification time as Provenance.Timestamp. mtime is not preserved by
// git, so the exact same committed file produces a different timestamp
// - and therefore different compiled output - on every fresh checkout,
// which is exactly the class of non-reproducible value this project's
// byte-identical-output principle (NFR-3) forbids. This proves the fix:
// changing a file's mtime without a new commit must not change the
// Timestamp Parse reports for facts from that file.
func TestParseTimestampTracksGitCommitNotModTime(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "example" {
  bucket = "a"
}
`)
	initGitRepo(t, dir)

	before, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse (before touch): %v", err)
	}
	wantTimestamp := resourceByAddress(t, before, ResourceAddress{Type: "aws_s3_bucket", Name: "example"}).Provenance.Timestamp

	future := time.Now().Add(72 * time.Hour)
	mainTF := filepath.Join(dir, "main.tf")
	if err := os.Chtimes(mainTF, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	after, err := Parse(dir)
	if err != nil {
		t.Fatalf("Parse (after touch): %v", err)
	}
	gotTimestamp := resourceByAddress(t, after, ResourceAddress{Type: "aws_s3_bucket", Name: "example"}).Provenance.Timestamp

	if !gotTimestamp.Equal(wantTimestamp) {
		t.Errorf("Timestamp changed after touching mtime with no new commit: got %s, want unchanged %s (Timestamp must track git commit time, not filesystem mtime)", gotTimestamp, wantTimestamp)
	}
}
