package ir

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// SchemaVersion is this package's own JSON schema version (FR-5.4),
// independent of any framework dataset's version. Bump it whenever
// Node's, Edge's, or Attestation's serialized shape changes in a way
// that breaks an old artifact's readability, and add a migration path
// for existing artifacts rather than just changing the number.
const SchemaVersion = "1"

// Graph is an in-memory evidence graph: a set of nodes (facts), edges
// (relationships between them), and attestations (human testimony for a
// control's non-derivable portion, FR-5.8), per FR-5.1. It is not itself
// a serialization format - WriteNodesJSONL, WriteEdgesJSONL, and
// WriteAttestationsJSONL write its three parts as independent JSON Lines
// streams (see their doc comments for why they're kept separate rather
// than merged into one mixed stream).
type Graph struct {
	Nodes        []Node
	Edges        []Edge
	Attestations []Attestation
}

// Validate checks every node, edge, and attestation in g for internal
// well-formedness, that no two nodes (or two attestations) share an ID,
// and that every edge's From and To reference a node actually present in
// g.Nodes. A dangling edge - one whose endpoint was dropped or never
// added - must fail here, loudly and cheaply, rather than surface later
// as a nil lookup or a silently-skipped edge in whatever consumes the
// graph next. A duplicate ID gets the same treatment: silently keeping
// the last one seen (what a naive map[NodeID]Node build would do) would
// make one of the two entries disappear from the graph with no
// indication which, or that anything was lost at all.
func (g Graph) Validate() error {
	ids := make(map[NodeID]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		if err := n.Validate(); err != nil {
			return err
		}
		if ids[n.ID] {
			return fmt.Errorf("ir: duplicate node ID %q", n.ID)
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
	attestationIDs := make(map[AttestationID]bool, len(g.Attestations))
	for _, a := range g.Attestations {
		if err := a.Validate(); err != nil {
			return err
		}
		if attestationIDs[a.ID] {
			return fmt.Errorf("ir: duplicate attestation ID %q", a.ID)
		}
		attestationIDs[a.ID] = true
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

// WriteAttestationsJSONL writes attestations to w as JSON Lines, sorted
// by ID, so the output is byte-identical for the same set of
// attestations regardless of build order (FR-5.3).
func WriteAttestationsJSONL(w io.Writer, attestations []Attestation) error {
	return writeJSONL(w, attestations, func(a, b Attestation) bool { return a.ID < b.ID })
}

// ReadAttestationsJSONL reads a JSON Lines stream of attestations
// written by WriteAttestationsJSONL.
func ReadAttestationsJSONL(r io.Reader) ([]Attestation, error) { return readJSONL[Attestation](r) }

// writeJSONL sorts items by less and writes them to w as JSON Lines, one
// compact, HTML-escape-free object per line. Node, Edge, and Attestation
// are the only instantiations today, but the shape (encode, sort, one
// item per line) is the same for all three, so it's written once here
// rather than three times.
//
// less alone is not always a total order: two Edges can share the same
// (From, To, Relationship) - e.g. one collector Declares a relationship
// that a live API call independently Observes - while differing in
// Provenance or SchemaVersion, fields less deliberately excludes. Encoding
// every item up front and breaking less's ties by comparing the encoded
// bytes gives a total order derived entirely from each item's own content,
// so the sorted (and therefore written) order never depends on the slice's
// incoming order - the byte-identical-regardless-of-build-order guarantee
// this package documents.
func writeJSONL[T any](w io.Writer, items []T, less func(a, b T) bool) error {
	type encodedItem struct {
		item T
		line []byte
	}
	enc := make([]encodedItem, len(items))
	for i, item := range items {
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		if err := e.Encode(item); err != nil {
			return fmt.Errorf("ir: encode item %d: %w", i, err)
		}
		enc[i] = encodedItem{item: item, line: buf.Bytes()}
	}
	sort.Slice(enc, func(i, j int) bool {
		if less(enc[i].item, enc[j].item) {
			return true
		}
		if less(enc[j].item, enc[i].item) {
			return false
		}
		return bytes.Compare(enc[i].line, enc[j].line) < 0
	})
	for _, e := range enc {
		if _, err := w.Write(e.line); err != nil {
			return fmt.Errorf("ir: write item: %w", err)
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
