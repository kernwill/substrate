package terraform

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/kernwill/substrate/internal/frontend/vcs"
	"github.com/kernwill/substrate/internal/provenance"
)

// CollectorVersion is this package's own collector version (FR-4.1),
// bumped whenever a change here could produce different facts from the
// same configuration. It is independent of the overall substrate binary
// version.
const CollectorVersion = "terraform/v0.1.0"

// Parse reads every *.tf file directly in dir (not recursively - a
// Terraform root module's own files live at one level; a subdirectory
// is a separate module this package does not yet expand, see doc.go)
// and returns the resource graph they declare.
//
// Resources are returned sorted by address, and files are read in
// sorted path order, so Parse's own output does not depend on the
// filesystem's directory-listing order - the frontend equivalent of the
// IR's byte-reproducibility requirement (FR-5.3), applied here because
// there is no reason for a parser to be nondeterministic even though
// this package's own contract doesn't cite that requirement by number.
func Parse(dir string) (*ResourceGraph, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		return nil, fmt.Errorf("terraform: glob %s: %w", dir, err)
	}
	sort.Strings(matches)

	parser := hclparse.NewParser()
	var files []*hclsyntax.Body
	commitTimes := make(map[string]time.Time, len(matches))
	for _, path := range matches {
		f, diags := parser.ParseHCLFile(path)
		if diags.HasErrors() {
			return nil, fmt.Errorf("terraform: parse %s: %w", path, diags)
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			return nil, fmt.Errorf("terraform: %s: unsupported HCL body implementation", path)
		}
		t, err := vcs.CommitTime(dir, filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf("terraform: %s: %w", path, err)
		}
		commitTimes[path] = t
		files = append(files, body)
	}

	variables := collectVariables(files)

	type pendingResource struct {
		addr     ResourceAddress
		body     *hclsyntax.Body
		defRange hcl.Range
	}
	var pending []pendingResource
	declaredAt := make(map[ResourceAddress]hcl.Range)
	for _, body := range files {
		for _, blk := range body.Blocks {
			if blk.Type != "resource" {
				continue
			}
			if len(blk.Labels) != 2 {
				return nil, fmt.Errorf("terraform: %s: resource block must have exactly two labels (type, name), got %d", blk.DefRange().Filename, len(blk.Labels))
			}
			addr := ResourceAddress{Type: blk.Labels[0], Name: blk.Labels[1]}
			if prev, dup := declaredAt[addr]; dup {
				return nil, fmt.Errorf("terraform: %s:%d: duplicate resource %s, first declared at %s:%d",
					blk.DefRange().Filename, blk.DefRange().Start.Line, addr, prev.Filename, prev.Start.Line)
			}
			declaredAt[addr] = blk.DefRange()
			pending = append(pending, pendingResource{addr: addr, body: blk.Body, defRange: blk.DefRange()})
		}
	}

	sort.Slice(pending, func(i, j int) bool {
		if pending[i].addr.Type != pending[j].addr.Type {
			return pending[i].addr.Type < pending[j].addr.Type
		}
		return pending[i].addr.Name < pending[j].addr.Name
	})

	graph := &ResourceGraph{}
	for _, r := range pending {
		eval := &resourceEval{variables: variables}
		attrs := redactAttributes(eval.evalBody(r.body, ""))
		graph.Resources = append(graph.Resources, Resource{
			Address:    r.addr,
			Attributes: attrs,
			References: eval.refs,
			Provenance: provenance.Record{
				SourceType:       "terraform",
				Locator:          provenance.Locator{Path: r.defRange.Filename, Line: r.defRange.Start.Line},
				Timestamp:        commitTimes[r.defRange.Filename],
				CollectorVersion: CollectorVersion,
				Basis:            provenance.Declared,
				Confidence:       provenance.Deterministic,
			},
		})
	}
	return graph, nil
}

// collectVariables evaluates every top-level "variable" block's
// "default" attribute across files and returns the resolved defaults,
// keyed by variable name. A variable with no default, or whose default
// cannot itself be statically evaluated (vanishingly rare in practice,
// since a default is normally a plain literal), is simply absent from
// the result - evalVarReference treats an absent variable as Unresolved
// rather than this function failing the whole parse over one variable.
func collectVariables(files []*hclsyntax.Body) map[string]any {
	variables := make(map[string]any)
	for _, body := range files {
		for _, blk := range body.Blocks {
			if blk.Type != "variable" || len(blk.Labels) != 1 {
				continue
			}
			attr, ok := blk.Body.Attributes["default"]
			if !ok {
				continue
			}
			val, diags := attr.Expr.Value(nil)
			if diags.HasErrors() {
				continue
			}
			goVal, err := ctyToGo(val)
			if err != nil {
				continue
			}
			variables[blk.Labels[0]] = goVal
		}
	}
	return variables
}

// resourceEval evaluates one resource block's body into
// AttributeValues, accumulating any resource-to-resource References
// found along the way (FR-2.1's resource graph edges).
type resourceEval struct {
	variables map[string]any
	refs      []Reference
}

// evalBody evaluates body's own attributes and nested blocks. path is
// the dot-joined attribute path from the resource root to body (empty
// for the resource's own top-level body), used to label References
// found anywhere in the tree with where they were found, not just what
// they point to.
func (e *resourceEval) evalBody(body *hclsyntax.Body, path string) map[string]AttributeValue {
	values := make(map[string]AttributeValue, len(body.Attributes)+len(body.Blocks))
	for name, attr := range body.Attributes {
		values[name] = e.evalAttribute(attr.Expr, joinPath(path, name))
	}

	var blockTypes []string
	byType := make(map[string][]*hclsyntax.Block)
	for _, blk := range body.Blocks {
		if _, ok := byType[blk.Type]; !ok {
			blockTypes = append(blockTypes, blk.Type)
		}
		byType[blk.Type] = append(byType[blk.Type], blk)
	}
	for _, typeName := range blockTypes {
		blocks := byType[typeName]
		blockPath := joinPath(path, typeName)
		if len(blocks) == 1 {
			values[typeName] = AttributeValue{Value: e.evalBody(blocks[0].Body, blockPath)}
			continue
		}
		list := make([]map[string]AttributeValue, len(blocks))
		for i, blk := range blocks {
			list[i] = e.evalBody(blk.Body, fmt.Sprintf("%s[%d]", blockPath, i))
		}
		values[typeName] = AttributeValue{Value: list}
	}
	return values
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// evalAttribute resolves one attribute expression, per FR-2.3: a pure
// literal (no free variables at all) is evaluated directly; a single
// reference to a known-shape name (var.X, or what is presumed to be a
// resource address) is handled specifically; anything else - a data
// source, a local, count/for_each metadata, an expression combining a
// reference with other content (string interpolation, a function call
// over a reference, an indexed traversal) - is Unresolved with a
// specific reason. Never guessed.
func (e *resourceEval) evalAttribute(expr hcl.Expression, path string) AttributeValue {
	if len(expr.Variables()) == 0 {
		val, diags := expr.Value(nil)
		if diags.HasErrors() {
			return AttributeValue{Unresolved: fmt.Sprintf("could not evaluate expression: %s", diags.Error())}
		}
		goVal, err := ctyToGo(val)
		if err != nil {
			return AttributeValue{Unresolved: fmt.Sprintf("could not represent evaluated value: %v", err)}
		}
		return AttributeValue{Value: goVal}
	}

	trav, ok := expr.(*hclsyntax.ScopeTraversalExpr)
	if !ok {
		return AttributeValue{Unresolved: "expression combines a reference with other content (interpolation, a function call, or an operator), which this package does not partially evaluate"}
	}
	root, rest, ok := splitTraversal(trav.Traversal)
	if !ok {
		return AttributeValue{Unresolved: "expression uses indexed or otherwise unsupported traversal syntax"}
	}

	switch root {
	case "var":
		return e.evalVarReference(rest)
	case "local":
		return AttributeValue{Unresolved: "references a local value, which this package does not evaluate"}
	case "data":
		return AttributeValue{Unresolved: "references a data source; its value is not known statically and is only available after Terraform runs it"}
	case "each", "count":
		return AttributeValue{Unresolved: fmt.Sprintf("references %s.*, which this package does not evaluate", root)}
	case "path", "terraform", "module":
		return AttributeValue{Unresolved: fmt.Sprintf("references %s.*, which this package does not evaluate", root)}
	default:
		return e.evalResourceReference(root, rest, path)
	}
}

// evalVarReference resolves "var.NAME" (rest == ["NAME"]) against
// e.variables. Anything deeper ("var.NAME.field") is Unresolved: this
// package resolves a variable's own default value, not further access
// into it.
func (e *resourceEval) evalVarReference(rest []string) AttributeValue {
	if len(rest) != 1 {
		return AttributeValue{Unresolved: "accesses a field of a variable's value, which this package does not evaluate"}
	}
	val, ok := e.variables[rest[0]]
	if !ok {
		return AttributeValue{Unresolved: fmt.Sprintf("variable %q has no statically-known default value", rest[0])}
	}
	return AttributeValue{Value: val}
}

// evalResourceReference records a reference to another resource in the
// same configuration and returns the corresponding Unresolved
// AttributeValue - see Reference's doc comment for why a resource
// reference is always both, never just one or the other.
func (e *resourceEval) evalResourceReference(resourceType string, rest []string, path string) AttributeValue {
	if len(rest) == 0 {
		return AttributeValue{Unresolved: fmt.Sprintf("expression %q does not resolve to a known variable or resource reference", resourceType)}
	}
	target := ResourceAddress{Type: resourceType, Name: rest[0]}
	targetAttr := strings.Join(rest[1:], ".")
	e.refs = append(e.refs, Reference{Attribute: path, Target: target, TargetAttribute: targetAttr})

	reason := fmt.Sprintf("value of %s", target)
	if targetAttr != "" {
		reason = fmt.Sprintf("value of %s.%s", target, targetAttr)
	}
	return AttributeValue{Unresolved: reason + " is only known after Terraform applies this configuration against a real provider; see this resource's references"}
}

// splitTraversal splits an hcl.Traversal into its root name and the
// dot-path of attribute names after it, e.g. "aws_s3_bucket.example.id"
// splits into ("aws_s3_bucket", ["example", "id"]). ok is false for any
// traversal containing an index step (trav[N]-style access), which this
// package does not support.
func splitTraversal(trav hcl.Traversal) (root string, rest []string, ok bool) {
	if len(trav) == 0 {
		return "", nil, false
	}
	r, isRoot := trav[0].(hcl.TraverseRoot)
	if !isRoot {
		return "", nil, false
	}
	for _, step := range trav[1:] {
		attr, isAttr := step.(hcl.TraverseAttr)
		if !isAttr {
			return "", nil, false
		}
		rest = append(rest, attr.Name)
	}
	return r.Name, rest, true
}

// ctyToGo converts a fully-known cty.Value into the same shape
// encoding/json produces from unmarshaling arbitrary JSON (string,
// bool, float64, []any, map[string]any, or nil), round-tripping through
// cty's own JSON codec rather than hand-rolling a type switch over
// every cty type.
func ctyToGo(v cty.Value) (any, error) {
	if v.IsNull() {
		return nil, nil
	}
	if !v.IsWhollyKnown() {
		return nil, fmt.Errorf("value is not fully known")
	}
	raw, err := ctyjson.Marshal(v, v.Type())
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
