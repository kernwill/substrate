package dockerfile

import (
	"testing"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

func TestToIR(t *testing.T) {
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

	// builder (pinned) and the final unnamed stage (unpinned) are both
	// external -> 2 nodes. test (FROM builder) is a local-stage
	// reference, not an external component -> no node.
	if len(irGraph.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(irGraph.Nodes))
	}

	byID := make(map[ir.NodeID]ir.Node, len(irGraph.Nodes))
	for _, n := range irGraph.Nodes {
		byID[n.ID] = n
	}

	builderAddr := StageAddress{Path: "../../../testdata/fixtures/minimal/Dockerfile", Index: 0, Name: "builder"}
	builder, ok := byID[nodeID(builderAddr)]
	if !ok {
		t.Fatalf("no node for %s (have: %v)", builderAddr, keys(byID))
	}
	if builder.ControlFamily != "SR" || len(builder.Controls) != 1 || builder.Controls[0] != (ir.Control{Family: "SR", Base: 11}) {
		t.Errorf("builder control = %+v/%+v, want SR/SR-11", builder.ControlFamily, builder.Controls)
	}
	if got, want := builder.Attributes["pinned_to_digest"], "true"; got != want {
		t.Errorf("builder pinned_to_digest = %q, want %q", got, want)
	}
	if builder.Provenance.Basis != "declared" {
		t.Errorf("builder Provenance.Basis = %q, want declared", builder.Provenance.Basis)
	}

	finalAddr := StageAddress{Path: "../../../testdata/fixtures/minimal/Dockerfile", Index: 2}
	final, ok := byID[nodeID(finalAddr)]
	if !ok {
		t.Fatalf("no node for %s (have: %v)", finalAddr, keys(byID))
	}
	if got, want := final.Attributes["pinned_to_digest"], "false"; got != want {
		t.Errorf("final pinned_to_digest = %q, want %q (tag-only, not pinned)", got, want)
	}
	if got, want := final.Attributes["tag"], "latest"; got != want {
		t.Errorf("final tag = %q, want %q", got, want)
	}
	if _, ok := final.Attributes["digest"]; ok {
		t.Error("final has a digest attribute, want none (no digest was given)")
	}

	testAddr := StageAddress{Path: "../../../testdata/fixtures/minimal/Dockerfile", Index: 1, Name: "test"}
	if _, ok := byID[nodeID(testAddr)]; ok {
		t.Error("test stage has a node, want none (FROM builder is a local-stage reference, not an external component)")
	}
}

func TestMapBaseImageAuthenticitySkipsNonExternalAndUnresolved(t *testing.T) {
	cases := []struct {
		name  string
		stage Stage
	}{
		{"scratch", Stage{Image: BaseImage{Kind: BaseImageScratch}, Provenance: deterministicProvenance()}},
		{"local_stage", Stage{Image: BaseImage{Kind: BaseImageLocalStage}, Provenance: deterministicProvenance()}},
		{"unresolved", Stage{Image: BaseImage{}, Provenance: unresolvedProvenance()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := mapBaseImageAuthenticity(c.stage); ok {
				t.Errorf("mapBaseImageAuthenticity(%s) = ok, want no node", c.name)
			}
		})
	}
}

func keys(m map[ir.NodeID]ir.Node) []ir.NodeID {
	out := make([]ir.NodeID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func deterministicProvenance() provenance.Record {
	return provenance.Record{
		SourceType:       "dockerfile",
		Locator:          provenance.Locator{Path: "Dockerfile", Line: 1},
		CollectorVersion: CollectorVersion,
		Basis:            provenance.Declared,
		Confidence:       provenance.Deterministic,
	}
}

func unresolvedProvenance() provenance.Record {
	r := deterministicProvenance()
	r.Confidence = provenance.Unresolved
	r.UnresolvedReason = "simulated"
	return r
}
