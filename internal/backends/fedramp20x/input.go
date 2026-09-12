package fedramp20x

import (
	"sort"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/rules"
)

// regoInput is the JSON shape passed as input to every KSI family's Rego
// module.
//
// Nodes carries every node in the evidence graph regardless of which
// family is being evaluated - a family's own module only ever looks at
// the controls it cares about, and rebuilding a family-filtered slice per
// evaluation would just be the same data recomputed once per family for
// no benefit. Indicators is scoped to the one family being evaluated,
// since that's what a single module's "input.indicators" is meant to
// answer questions about.
type regoInput struct {
	Nodes      []regoNode               `json:"nodes"`
	Indicators map[string]regoIndicator `json:"indicators"`
}

type regoNode struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Controls []string `json:"controls"`
}

type regoIndicator struct {
	Controls []string `json:"controls"`
}

// buildInput renders g's nodes and theme's indicators into the shape
// every KSI family module expects. Controls are rendered in OSCAL form
// (ir.Control.String(), e.g. "sc-28.1") on the node side; the indicator
// side is taken verbatim, since rules.KSIIndicator.Controls is already
// OSCAL form straight from the vendored dataset (see its own doc
// comment). The two line up as plain strings without either side needing
// internal/rules.ControlID's other two notations (CTL-key, FedRAMP
// prose) - this package only ever needs to ask "does the graph have a
// node naming this exact control," never to reformat one.
//
// Node and control order is sorted before serializing, even though Rego
// set/array semantics don't require it for correctness, because a Rego
// module's array comprehensions (results' evidence_for, specifically) can
// reflect input iteration order into their own output order - sorting
// here is what keeps that output reproducible (FR-5.3's discipline,
// applied to this backend's own output too).
func buildInput(g ir.Graph, theme rules.KSITheme) regoInput {
	nodes := make([]regoNode, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		controls := make([]string, 0, len(n.Controls))
		for _, c := range n.Controls {
			controls = append(controls, c.String())
		}
		sort.Strings(controls)
		nodes = append(nodes, regoNode{ID: string(n.ID), Kind: n.Kind, Controls: controls})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	indicators := make(map[string]regoIndicator, len(theme.Indicators))
	for name, ind := range theme.Indicators {
		controls := append([]string(nil), ind.Controls...)
		sort.Strings(controls)
		indicators[name] = regoIndicator{Controls: controls}
	}

	return regoInput{Nodes: nodes, Indicators: indicators}
}
