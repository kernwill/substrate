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

// Validate checks every node and edge in g for internal well-formedness,
// and that every edge's From and To reference a node actually present in
// g.Nodes. A dangling edge - one whose endpoint was dropped or never
// added - must fail here, loudly and cheaply, rather than surface later
// as a nil lookup or a silently-skipped edge in whatever consumes the
// graph next.
func (g Graph) Validate() error {
	ids := make(map[NodeID]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		if err := n.Validate(); err != nil {
			return err
		}
		ids[n.ID] = true
	}
	for _, e := range g.Edges {
		if err := e.Validate(); err != nil {
			return err
		}
		if !ids[e.From] {
			return fmt.Errorf("ir: edge %s->%s: from-node %q is not in the graph", e.From, e.To, e.From)
		}
		if !ids[e.To] {
			return fmt.Errorf("ir: edge %s->%s: to-node %q is not in the graph", e.From, e.To, e.To)
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
	return writeJSONL(w, nodes, func(a, b Node) bool { return a.ID < b.ID })
}

// ReadNodesJSONL reads a JSON Lines stream of nodes written by
// WriteNodesJSONL (or anything producing the same shape). It does not
// require the sorted order WriteNodesJSONL produces - a hand-edited or
// concatenated file is still readable - since sortedness is an output
// guarantee of this package, not an input requirement.
func ReadNodesJSONL(r io.Reader) ([]Node, error) { return readJSONL[Node](r) }

// WriteEdgesJSONL writes edges to w as JSON Lines, sorted by
// (From, To, Relationship) so the output is byte-identical for the same
// set of edges regardless of build order (FR-5.3).
func WriteEdgesJSONL(w io.Writer, edges []Edge) error {
	return writeJSONL(w, edges, func(a, b Edge) bool {
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Relationship < b.Relationship
	})
}

// ReadEdgesJSONL reads a JSON Lines stream of edges written by
// WriteEdgesJSONL.
func ReadEdgesJSONL(r io.Reader) ([]Edge, error) { return readJSONL[Edge](r) }

// writeJSONL sorts a copy of items by less and writes them to w as JSON
// Lines, one compact, HTML-escape-free object per line. Node and Edge
// are the only two instantiations today, but the shape (sort a copy,
// encode with escaping disabled, one item per line) is the same for
// either, so it's written once here rather than twice.
func writeJSONL[T any](w io.Writer, items []T, less func(a, b T) bool) error {
	sorted := make([]T, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool { return less(sorted[i], sorted[j]) })

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i, item := range sorted {
		if err := enc.Encode(item); err != nil {
			return fmt.Errorf("ir: write item %d: %w", i, err)
		}
	}
	return nil
}

// readJSONL reads a JSON Lines stream into a slice of T, skipping blank
// lines.
func readJSONL[T any](r io.Reader) ([]T, error) {
	var items []T
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var item T
		if err := json.Unmarshal(b, &item); err != nil {
			return nil, fmt.Errorf("ir: read: line %d: %w", line, err)
		}
		items = append(items, item)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("ir: read: %w", err)
	}
	return items, nil
}
