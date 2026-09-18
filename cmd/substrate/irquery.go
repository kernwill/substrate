package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kernwill/substrate/internal/ir"
	"github.com/kernwill/substrate/internal/provenance"
)

// runIR dispatches "substrate ir <subcommand>" - today only "query"
// (FR-5.5), matching the same subcommand shape "substrate rules
// show"/"substrate rules diff" already use.
func runIR(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "substrate ir: no subcommand given (try: query)")
		return 2
	}
	switch args[0] {
	case "query":
		return runIRQuery(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "substrate ir: %q not implemented yet (try: query)\n", args[0])
		return 2
	}
}

// controlQuery is a parsed --control value: a family, a base control
// number, and an optional enhancement. HasEnhancement false means "any
// enhancement, or the base control itself" - querying "AC-2" returns
// AC-2, AC-2(1), AC-2(2), and so on, since an enhancement's evidence
// still bears on the control FR-5.5 is asking about. HasEnhancement
// true (querying "AC-2(1)" or "AC-2.1") narrows to that exact
// enhancement only.
type controlQuery struct {
	Family         ir.ControlFamily
	Base           int
	Enhancement    int
	HasEnhancement bool
}

// controlQueryPattern accepts the three notations a caller might
// reasonably type: "AC-2", "AC-2.1" (OSCAL-style dotted), and "AC-2(1)"
// (FedRAMP prose-style parenthetical) - matching the same three-notation
// tolerance internal/rules.ParseControlID already established for the
// vendored dataset, applied here to the IR's own, framework-agnostic
// Control type instead.
var controlQueryPattern = regexp.MustCompile(`(?i)^([A-Za-z]{2})-(\d{1,2})(?:[.\(](\d{1,2})\)?)?$`)

// parseControlQuery parses --control's value. Accepts "AC-2",
// "ac-2.1", and "AC-2(1)"; rejects anything else with a real error -
// never a guess at what the caller meant.
func parseControlQuery(s string) (controlQuery, error) {
	m := controlQueryPattern.FindStringSubmatch(s)
	if m == nil {
		return controlQuery{}, fmt.Errorf("%q is not a recognized control ID (want e.g. AC-2, AC-2.1, or AC-2(1))", s)
	}
	base, err := strconv.Atoi(m[2])
	if err != nil {
		return controlQuery{}, fmt.Errorf("%q: invalid base control number: %w", s, err)
	}
	q := controlQuery{Family: ir.ControlFamily(strings.ToUpper(m[1])), Base: base}
	if m[3] != "" {
		enhancement, err := strconv.Atoi(m[3])
		if err != nil {
			return controlQuery{}, fmt.Errorf("%q: invalid enhancement number: %w", s, err)
		}
		q.Enhancement = enhancement
		q.HasEnhancement = true
	}
	return q, nil
}

// matchesControl reports whether any of controls bears on q, per
// controlQuery's own doc comment on enhancement matching.
func (q controlQuery) matchesControl(controls []ir.Control) bool {
	for _, c := range controls {
		if c.Family != q.Family || c.Base != q.Base {
			continue
		}
		if !q.HasEnhancement {
			return true
		}
		if c.Enhancement == q.Enhancement {
			return true
		}
	}
	return false
}

// matchesFamilyOnly reports whether family alone bears on q, for a node
// or attestation whose Controls list is empty (FR-5.2's "enumerated
// where unambiguous" allows a fact to carry only its ControlFamily) -
// such a fact still bears on any query for that same family, but
// cannot answer a query that asks for a specific base control or
// enhancement, since it never claimed to know one.
func (q controlQuery) matchesFamilyOnly(family ir.ControlFamily) bool {
	return family == q.Family
}

// runIRQuery implements "substrate ir query --dir <dir> --control <ID>
// [--format text|json]" (FR-5.5, and FR-4.6's "full derivation chain
// queryable for any assertion" applied to the one hop FR-5.5 itself
// asks for: every matching fact's own provenance).
//
// --dir names the "ir" directory a prior "substrate compile" wrote
// (<out>/ir) - nodes.jsonl is required; attestations.jsonl is read
// too if present (compile does not write one today, since FR-5.8's
// Attestation type has no producer yet, but a future one - or a
// hand-authored file - should be picked up here with no code change).
// edges.jsonl is not searched: an Edge is a relationship between two
// facts, not itself a fact bearing on a control, so it is out of
// FR-5.5's own "returns all bearing facts" scope.
func runIRQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("substrate ir query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory containing nodes.jsonl (and, if present, attestations.jsonl) from 'substrate compile'")
	control := fs.String("control", "", "control ID to query, e.g. AC-2, AC-2.1, or AC-2(1)")
	format := fs.String("format", "text", "output format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: substrate ir query --dir <dir> --control <ID> [--format text|json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *control == "" {
		fs.Usage()
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "substrate ir query: --format must be \"text\" or \"json\", got %q\n", *format)
		return 2
	}
	q, err := parseControlQuery(*control)
	if err != nil {
		fmt.Fprintf(stderr, "substrate ir query: --control: %v\n", err)
		return 2
	}

	nodes, err := readNodesJSONLFile(filepath.Join(*dir, "nodes.jsonl"))
	if err != nil {
		fmt.Fprintf(stderr, "substrate ir query: %v\n", err)
		return 2
	}
	var matchedNodes []ir.Node
	for _, n := range nodes {
		if q.matchesControl(n.Controls) || (len(n.Controls) == 0 && q.matchesFamilyOnly(n.ControlFamily)) {
			matchedNodes = append(matchedNodes, n)
		}
	}

	var matchedAttestations []ir.Attestation
	attestationsPath := filepath.Join(*dir, "attestations.jsonl")
	if _, statErr := os.Stat(attestationsPath); statErr == nil {
		attestations, err := readAttestationsJSONLFile(attestationsPath)
		if err != nil {
			fmt.Fprintf(stderr, "substrate ir query: %v\n", err)
			return 2
		}
		for _, a := range attestations {
			if q.matchesControl(a.Controls) || (len(a.Controls) == 0 && q.matchesFamilyOnly(a.ControlFamily)) {
				matchedAttestations = append(matchedAttestations, a)
			}
		}
	}

	if *format == "json" {
		return writeIRQueryJSON(stdout, matchedNodes, matchedAttestations)
	}
	writeIRQueryText(stdout, *control, matchedNodes, matchedAttestations)
	return 0
}

func readNodesJSONLFile(path string) ([]ir.Node, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	nodes, err := ir.ReadNodesJSONL(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return nodes, nil
}

func readAttestationsJSONLFile(path string) ([]ir.Attestation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	attestations, err := ir.ReadAttestationsJSONL(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return attestations, nil
}

func writeIRQueryJSON(stdout io.Writer, nodes []ir.Node, attestations []ir.Attestation) int {
	out := struct {
		Nodes        []ir.Node        `json:"nodes"`
		Attestations []ir.Attestation `json:"attestations,omitempty"`
	}{Nodes: nodes, Attestations: attestations}
	if err := writeJSON(stdout, out); err != nil {
		return 2
	}
	return 0
}

// writeIRQueryText renders matched facts as human-readable text, one
// block per fact, each ending with its full provenance - FR-5.5's
// "with provenance" is not optional detail, it's the point: a fact with
// no traceable source is worthless (internal/provenance's own package
// doc comment).
func writeIRQueryText(stdout io.Writer, control string, nodes []ir.Node, attestations []ir.Attestation) {
	if len(nodes) == 0 && len(attestations) == 0 {
		fmt.Fprintf(stdout, "no facts bearing on %s were found\n", control)
		return
	}
	for i, n := range nodes {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprintf(stdout, "node %s\n", n.ID)
		fmt.Fprintf(stdout, "  kind:            %s\n", n.Kind)
		fmt.Fprintf(stdout, "  control_family:  %s\n", n.ControlFamily)
		if len(n.Controls) > 0 {
			names := make([]string, len(n.Controls))
			for j, c := range n.Controls {
				names[j] = c.String()
			}
			fmt.Fprintf(stdout, "  controls:        %s\n", strings.Join(names, ", "))
		}
		for _, k := range sortedAttributeKeys(n.Attributes) {
			fmt.Fprintf(stdout, "  attribute %s: %s\n", k, n.Attributes[k])
		}
		writeProvenanceText(stdout, n.Provenance)
	}
	for i, a := range attestations {
		if i > 0 || len(nodes) > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprintf(stdout, "attestation %s\n", a.ID)
		fmt.Fprintf(stdout, "  control_family:  %s\n", a.ControlFamily)
		fmt.Fprintf(stdout, "  statement:       %s\n", a.Statement)
		fmt.Fprintf(stdout, "  attester:        %s\n", a.Attester)
		writeProvenanceText(stdout, a.Provenance)
	}
}

// writeProvenanceText renders p's full derivation chain (FR-4.6): where
// the fact came from, when, by what collector version, and whether it
// is Declared or Observed, Deterministic or Unresolved.
func writeProvenanceText(stdout io.Writer, p provenance.Record) {
	fmt.Fprintf(stdout, "  source:          %s\n", p.SourceType)
	if p.Locator.Path != "" {
		fmt.Fprintf(stdout, "  location:        %s:%d\n", p.Locator.Path, p.Locator.Line)
	} else if p.Locator.API != "" {
		fmt.Fprintf(stdout, "  location:        %s\n", p.Locator.API)
	}
	fmt.Fprintf(stdout, "  observed_at:     %s\n", p.Timestamp.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(stdout, "  collector:       %s\n", p.CollectorVersion)
	fmt.Fprintf(stdout, "  basis:           %s\n", p.Basis)
	fmt.Fprintf(stdout, "  confidence:      %s\n", p.Confidence)
	if p.UnresolvedReason != "" {
		fmt.Fprintf(stdout, "  unresolved_reason: %s\n", p.UnresolvedReason)
	}
}

func sortedAttributeKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
