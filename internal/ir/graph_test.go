package ir

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteReadNodesJSONLRoundTrip(t *testing.T) {
	want := []Node{validNode("n1"), validNode("n2"), validNode("n3")}

	var buf bytes.Buffer
	if err := WriteNodesJSONL(&buf, want); err != nil {
		t.Fatalf("WriteNodesJSONL: %v", err)
	}

	got, err := ReadNodesJSONL(&buf)
	if err != nil {
		t.Fatalf("ReadNodesJSONL: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d nodes, want %d", len(got), len(want))
	}
	for i := range want {
		if err := got[i].Validate(); err != nil {
			t.Errorf("round-tripped node %d failed Validate(): %v", i, err)
		}
	}
}

func TestWriteNodesJSONLIsOneObjectPerLine(t *testing.T) {
	nodes := []Node{validNode("n1"), validNode("n2")}
	var buf bytes.Buffer
	if err := WriteNodesJSONL(&buf, nodes); err != nil {
		t.Fatalf("WriteNodesJSONL: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != len(nodes) {
		t.Fatalf("got %d lines, want %d (one JSON object per line)", len(lines), len(nodes))
	}
}

// TestWriteNodesJSONLSortsByID backs FR-5.3's "stable ordering... no map
// iteration order dependence": callers should never need to remember to
// sort nodes before writing them.
func TestWriteNodesJSONLSortsByID(t *testing.T) {
	unsorted := []Node{validNode("n3"), validNode("n1"), validNode("n2")}

	var buf bytes.Buffer
	if err := WriteNodesJSONL(&buf, unsorted); err != nil {
		t.Fatalf("WriteNodesJSONL: %v", err)
	}
	got, err := ReadNodesJSONL(&buf)
	if err != nil {
		t.Fatalf("ReadNodesJSONL: %v", err)
	}
	wantOrder := []NodeID{"n1", "n2", "n3"}
	for i, id := range wantOrder {
		if got[i].ID != id {
			t.Errorf("node[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

// TestWriteNodesJSONLIsByteReproducible backs FR-5.3 directly: writing
// the same set of nodes twice, from two independently-ordered slices,
// must produce byte-identical output.
func TestWriteNodesJSONLIsByteReproducible(t *testing.T) {
	a := []Node{validNode("n1"), validNode("n2"), validNode("n3")}
	b := []Node{validNode("n3"), validNode("n1"), validNode("n2")}

	var bufA, bufB bytes.Buffer
	if err := WriteNodesJSONL(&bufA, a); err != nil {
		t.Fatalf("WriteNodesJSONL(a): %v", err)
	}
	if err := WriteNodesJSONL(&bufB, b); err != nil {
		t.Fatalf("WriteNodesJSONL(b): %v", err)
	}
	if bufA.String() != bufB.String() {
		t.Errorf("output differs by input order:\n--- a ---\n%s\n--- b ---\n%s", bufA.String(), bufB.String())
	}
}

// TestWriteNodesJSONLDoesNotHTMLEscape guards against the same class of
// bug found in internal/rules: json.Encoder HTML-escapes "<", ">", "&"
// by default, which would silently corrupt a Locator path, an
// Attributes value, or anything else a collector puts into a Node
// verbatim from a customer's own source files.
func TestWriteNodesJSONLDoesNotHTMLEscape(t *testing.T) {
	n := validNode("n1")
	n.Attributes = map[string]string{"condition": "a > b && c < d"}

	var buf bytes.Buffer
	if err := WriteNodesJSONL(&buf, []Node{n}); err != nil {
		t.Fatalf("WriteNodesJSONL: %v", err)
	}
	if !strings.Contains(buf.String(), "a > b && c < d") {
		t.Errorf("output HTML-escaped node content, want it verbatim: %s", buf.String())
	}
}

func TestWriteReadEdgesJSONLRoundTrip(t *testing.T) {
	want := []Edge{validEdge("n1", "n2"), validEdge("n2", "n3")}

	var buf bytes.Buffer
	if err := WriteEdgesJSONL(&buf, want); err != nil {
		t.Fatalf("WriteEdgesJSONL: %v", err)
	}
	got, err := ReadEdgesJSONL(&buf)
	if err != nil {
		t.Fatalf("ReadEdgesJSONL: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d edges, want %d", len(got), len(want))
	}
	for i := range want {
		if err := got[i].Validate(); err != nil {
			t.Errorf("round-tripped edge %d failed Validate(): %v", i, err)
		}
	}
}

func TestWriteEdgesJSONLSortsByFromToRelationship(t *testing.T) {
	unsorted := []Edge{
		validEdge("n2", "n1"),
		validEdge("n1", "n2"),
		validEdge("n1", "n1"),
	}
	var buf bytes.Buffer
	if err := WriteEdgesJSONL(&buf, unsorted); err != nil {
		t.Fatalf("WriteEdgesJSONL: %v", err)
	}
	got, err := ReadEdgesJSONL(&buf)
	if err != nil {
		t.Fatalf("ReadEdgesJSONL: %v", err)
	}
	wantOrder := [][2]NodeID{{"n1", "n1"}, {"n1", "n2"}, {"n2", "n1"}}
	for i, want := range wantOrder {
		if got[i].From != want[0] || got[i].To != want[1] {
			t.Errorf("edge[%d] = %s->%s, want %s->%s", i, got[i].From, got[i].To, want[0], want[1])
		}
	}
}

func TestWriteEdgesJSONLIsByteReproducible(t *testing.T) {
	a := []Edge{validEdge("n1", "n2"), validEdge("n2", "n3")}
	b := []Edge{validEdge("n2", "n3"), validEdge("n1", "n2")}

	var bufA, bufB bytes.Buffer
	if err := WriteEdgesJSONL(&bufA, a); err != nil {
		t.Fatalf("WriteEdgesJSONL(a): %v", err)
	}
	if err := WriteEdgesJSONL(&bufB, b); err != nil {
		t.Fatalf("WriteEdgesJSONL(b): %v", err)
	}
	if bufA.String() != bufB.String() {
		t.Errorf("output differs by input order:\n--- a ---\n%s\n--- b ---\n%s", bufA.String(), bufB.String())
	}
}

func TestGraphValidate(t *testing.T) {
	g := Graph{
		Nodes: []Node{validNode("n1"), validNode("n2")},
		Edges: []Edge{validEdge("n1", "n2")},
	}
	if err := g.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	bad := g
	bad.Nodes = append([]Node{}, g.Nodes...)
	bad.Nodes[0].Kind = ""
	if err := bad.Validate(); err == nil {
		t.Error("Validate() = nil, want error propagated from an invalid node")
	}
}

// TestGraphValidateRejectsDanglingEdge is a regression test for a gap
// the code review's ultra pass found: Validate checked each node and
// edge for internal well-formedness but never that an edge's From/To
// actually referenced a node present in the graph.
func TestGraphValidateRejectsDanglingEdgeFrom(t *testing.T) {
	g := Graph{
		Nodes: []Node{validNode("n2")},
		Edges: []Edge{validEdge("n1", "n2")}, // "n1" is not in Nodes
	}
	if err := g.Validate(); err == nil {
		t.Error("Validate() = nil, want error for an edge whose From-node is not in the graph")
	}
}

func TestGraphValidateRejectsDanglingEdgeTo(t *testing.T) {
	g := Graph{
		Nodes: []Node{validNode("n1")},
		Edges: []Edge{validEdge("n1", "n2")}, // "n2" is not in Nodes
	}
	if err := g.Validate(); err == nil {
		t.Error("Validate() = nil, want error for an edge whose To-node is not in the graph")
	}
}

func TestReadNodesJSONLSkipsBlankLines(t *testing.T) {
	r := strings.NewReader("\n\n")
	nodes, err := ReadNodesJSONL(r)
	if err != nil {
		t.Fatalf("ReadNodesJSONL: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("got %d nodes from blank input, want 0", len(nodes))
	}
}

func TestReadNodesJSONLRejectsMalformedLine(t *testing.T) {
	r := strings.NewReader("{not json}\n")
	if _, err := ReadNodesJSONL(r); err == nil {
		t.Error("ReadNodesJSONL(malformed) succeeded, want error")
	}
}
