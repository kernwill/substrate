package terraform

import (
	"testing"

	"github.com/kernwill/substrate/internal/ir"
)

// TestToIRVendoredMinimalFixture is FR-5.8/5.9's mapping layer's own
// done criterion: convert the real vendored fixture's resource graph
// and check exactly the reviewed mappings fire, with exactly the
// reviewed control assignments, and that the resulting graph validates.
func TestToIRVendoredMinimalFixture(t *testing.T) {
	g, err := Parse("../../../testdata/fixtures/minimal")
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
		t.Fatalf("got %d nodes, want 3 (bare aws_s3_bucket has no mapping)", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	versioning, ok := byID[nodeID(ResourceAddress{Type: "aws_s3_bucket_versioning", Name: "example"})]
	if !ok {
		t.Fatal("no node for aws_s3_bucket_versioning.example")
	}
	if versioning.ControlFamily != "CP" || len(versioning.Controls) != 1 || versioning.Controls[0] != (ir.Control{Family: "CP", Base: 9}) {
		t.Errorf("versioning node control = %+v/%+v, want CP/CP-9", versioning.ControlFamily, versioning.Controls)
	}
	if got, want := versioning.Attributes["status"], "Enabled"; got != want {
		t.Errorf("versioning status = %q, want %q", got, want)
	}

	encryption, ok := byID[nodeID(ResourceAddress{Type: "aws_s3_bucket_server_side_encryption_configuration", Name: "example"})]
	if !ok {
		t.Fatal("no node for aws_s3_bucket_server_side_encryption_configuration.example")
	}
	if encryption.ControlFamily != "SC" || len(encryption.Controls) != 1 || encryption.Controls[0] != (ir.Control{Family: "SC", Base: 28, Enhancement: 1}) {
		t.Errorf("encryption node control = %+v/%+v, want SC/SC-28(1)", encryption.ControlFamily, encryption.Controls)
	}
	if got, want := encryption.Attributes["sse_algorithm"], "aws:kms"; got != want {
		t.Errorf("sse_algorithm = %q, want %q", got, want)
	}

	pab, ok := byID[nodeID(ResourceAddress{Type: "aws_s3_bucket_public_access_block", Name: "example"})]
	if !ok {
		t.Fatal("no node for aws_s3_bucket_public_access_block.example")
	}
	if pab.ControlFamily != "AC" || len(pab.Controls) != 1 || pab.Controls[0] != (ir.Control{Family: "AC", Base: 3}) {
		t.Errorf("public access block node control = %+v/%+v, want AC/AC-3", pab.ControlFamily, pab.Controls)
	}
	for _, flag := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		if got, want := pab.Attributes[flag], "true"; got != want {
			t.Errorf("public access block %s = %q, want %q", flag, got, want)
		}
	}

	if _, ok := byID[nodeID(ResourceAddress{Type: "aws_s3_bucket", Name: "example"})]; ok {
		t.Error("bare aws_s3_bucket produced a node, want none - it has no reviewed mapping")
	}

	// All three mapped resources reference aws_s3_bucket.example, which
	// has no node of its own - so there should be no edges at all.
	if len(irGraph.Edges) != 0 {
		t.Errorf("got %d edges, want 0 (the referenced bucket has no IR node to link to)", len(irGraph.Edges))
	}
}

// TestToIREmitsEdgeWhenBothEndpointsHaveNodes is a synthetic case
// TestToIRVendoredMinimalFixture can't exercise (the vendored fixture's
// only referenced resource, the bare bucket, never gets a node): two
// mapped resources where one references the other should produce a
// real ir.Edge.
func TestToIREmitsEdgeWhenBothEndpointsHaveNodes(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket_versioning" "a" {
  bucket = "static-bucket-id"
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket_versioning.a.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
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
	if err := irGraph.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(irGraph.Nodes))
	}
	if len(irGraph.Edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(irGraph.Edges))
	}
	got := irGraph.Edges[0]
	wantFrom := nodeID(ResourceAddress{Type: "aws_s3_bucket_public_access_block", Name: "b"})
	wantTo := nodeID(ResourceAddress{Type: "aws_s3_bucket_versioning", Name: "a"})
	if got.From != wantFrom || got.To != wantTo || got.Relationship != "configures" || got.SchemaVersion != ir.SchemaVersion {
		t.Errorf("edge = %+v, want From=%s To=%s Relationship=configures SchemaVersion=%s", got, wantFrom, wantTo, ir.SchemaVersion)
	}
}

func TestMapVersioningIgnoresUnresolvedStatus(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
variable "status" {}

resource "aws_s3_bucket_versioning" "example" {
  bucket = "b"
  versioning_configuration {
    status = var.status
  }
}
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
		t.Errorf("got %d nodes, want 0 (unresolved status has nothing to measure)", len(irGraph.Nodes))
	}
}
