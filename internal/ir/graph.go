package ir

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// SchemaVersion is this package's own JSON schema version (FR-5.4),
// independent of any framework dataset's version. Bump it whenever
// Node's or Edge's serialized shape changes in a way that breaks an old
// artifact's readability, and add a migration path for existing
// artifacts rather than just changing the number.
const SchemaVersion = "1"

// Graph is an in-memory evidence graph: a set of nodes (facts) and
// edges (relationships between them), per FR-5.1. It is not itself a
// serialization format - WriteNodesJSONL and WriteEdgesJSONL write its
// two parts as two independent JSON Lines streams (see their doc
// comments for why they're kept separate rather than merged into one
// mixed stream).
type Graph struct {
	Nodes []Node
	Edges []Edge
}

// Validate checks every node and edge in g.
func (g Graph) Validate() error {
	for _, n := range g.Nodes {
		if err := n.Validate(); err != nil {
			return err
		}
	}
	for _, e := range g.Edges {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// WriteNodesJSONL writes nodes to w as JSON Lines (one compact JSON
// object per line), sorted by ID first, so the output is byte-identical
// for the same set of nodes regardless of what order the caller happened
// to build them in (FR-5.3) - callers should never need to remember to
// sort before writing themselves.
func WriteNodesJSONL(w io.Writer, nodes []Node) error {
	sorted := make([]Node, len(nodes))
	copy(sorted, nodes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, n := range sorted {
		if err := enc.Encode(n); err != nil {
			return fmt.Errorf("ir: write node %s: %w", n.ID, err)
		}
	}
	return nil
}

// ReadNodesJSONL reads a JSON Lines stream of nodes written by
// WriteNodesJSONL (or anything producing the same shape). It does not
// require the sorted order WriteNodesJSONL produces - a hand-edited or
// concatenated file is still readable - since sortedness is an output
// guarantee of this package, not an input requirement.
func ReadNodesJSONL(r io.Reader) ([]Node, error) {
	var nodes []Node
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var n Node
		if err := json.Unmarshal(b, &n); err != nil {
			return nil, fmt.Errorf("ir: read nodes: line %d: %w", line, err)
		}
		nodes = append(nodes, n)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ir: read nodes: %w", err)
	}
	return nodes, nil
}

// WriteEdgesJSONL writes edges to w as JSON Lines, sorted by
// (From, To, Relationship) so the output is byte-identical for the same
// set of edges regardless of build order (FR-5.3).
func WriteEdgesJSONL(w io.Writer, edges []Edge) error {
	sorted := make([]Edge, len(edges))
	copy(sorted, edges)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Relationship < b.Relationship
	})

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, e := range sorted {
		if err := enc.Encode(e); err != nil {
			return fmt.Errorf("ir: write edge %s->%s: %w", e.From, e.To, err)
		}
	}
	return nil
}

// ReadEdgesJSONL reads a JSON Lines stream of edges written by
// WriteEdgesJSONL.
func ReadEdgesJSONL(r io.Reader) ([]Edge, error) {
	var edges []Edge
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var e Edge
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("ir: read edges: line %d: %w", line, err)
		}
		edges = append(edges, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ir: read edges: %w", err)
	}
	return edges, nil
}
